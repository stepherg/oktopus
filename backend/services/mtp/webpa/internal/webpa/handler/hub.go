package handler

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/OktopUSP/oktopus/webpa/internal/config"
	"github.com/gorilla/websocket"
)

// Keeps the content and the destination of a websockets message
type message struct {
	// Websockets client endpoint id, eid follows usp specification.
	// This field is needed for us to know which agent or controller
	// the message is intended to be delivered to.
	eid     string
	data    []byte
	msgType int
	from    string
}

// Hub maintains the set of active clients and broadcasts messages to the
// clients.
type Hub struct {
	mu sync.RWMutex

	// Registered clients.
	clients map[string]*Client

	// Inbound messages from the clients.
	broadcast chan message

	// Register requests from the clients.
	register chan *Client

	// Unregister requests from clients.
	unregister chan *Client
}

const (
	OFFLINE = "0"
	ONLINE  = "1"
)

type deviceStatus struct {
	Eid    string
	Status string
}

// Global hub instance
var hub *Hub

// Client configuration
var conf config.Config

func InitHandlers(c config.Config) {
	conf = c
	log.Println("New hub, Controller eid:", conf.ControllerEID)
	hub = newHub()

	go func() {
		hub.run()
	}()
}

func newHub() *Hub {
	return &Hub{
		broadcast:  make(chan message),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[string]*Client),
	}
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			if existing, ok := h.clients[client.eid]; ok && existing != client {
				close(existing.send)
			}
			// register new eid
			h.clients[client.eid] = client
			controllerClient, controllerConnected := h.clients[conf.ControllerEID]
			h.mu.Unlock()
			if client.eid != conf.ControllerEID {
				log.Printf("New device connected: %s", client.eid)
				data, _ := json.Marshal(deviceStatus{client.eid, ONLINE})
				msg := message{
					from:    "Webpa server",
					eid:     conf.ControllerEID,
					data:    data,
					msgType: websocket.TextMessage,
				}
				log.Printf("%++v", msg)
				if controllerConnected {
					select {
					// send message to receiver client
					case controllerClient.send <- msg:
						log.Printf("Sent a message %s --> %s", msg.from, msg.eid)
					default:
						// in case the msg sending fails, close the client connection
						// because it means that the client is no longer active
						log.Printf("Failed to send a msg to %s, disconnecting client...", msg.eid)
						h.mu.Lock()
						if current, ok := h.clients[controllerClient.eid]; ok && current == controllerClient {
							close(controllerClient.send)
							delete(h.clients, controllerClient.eid)
						}
						h.mu.Unlock()
					}
				}
			} else {
				log.Printf("New controller connected: %s", client.eid)
			}

		case client := <-h.unregister:
			h.mu.Lock()
			// verify if eid exists and still points at the disconnecting client
			if current, ok := h.clients[client.eid]; ok && current == client {
				// delete eid from map of connections
				delete(h.clients, client.eid)
				// close client messages receiving channel
				close(client.send)
			}
			controllerClient, controllerConnected := h.clients[conf.ControllerEID]
			h.mu.Unlock()
			log.Println("Disconnected client", client.eid)
			data, _ := json.Marshal(deviceStatus{client.eid, OFFLINE})
			msg := message{
				from:    "Webpa server",
				eid:     conf.ControllerEID,
				data:    data,
				msgType: websocket.TextMessage,
			}
			if controllerConnected {
				select {
				// send message to receiver client
				case controllerClient.send <- msg:
					log.Printf("Sent a message %s --> %s", msg.from, msg.eid)
				default:
					// in case the msg sending fails, close the client connection
					// because it means that the client is no longer active
					log.Printf("Failed to send a msg to %s, disconnecting client...", msg.eid)
					h.mu.Lock()
					if current, ok := h.clients[controllerClient.eid]; ok && current == controllerClient {
						close(controllerClient.send)
						delete(h.clients, controllerClient.eid)
					}
					h.mu.Unlock()
				}
			}
		case message := <-h.broadcast:
			log.Println("send message to", message.eid)
			// verify if eid exists
			h.mu.RLock()
			c, ok := h.clients[message.eid]
			h.mu.RUnlock()
			if ok {
				select {
				// send message to receiver client
				case c.send <- message:
					log.Printf("Sent a message %s --> %s", message.from, message.eid)
				default:
					// in case the message sending fails, close the client connection
					// because it means that the client is no longer active
					log.Printf("Failed to send a message to %s, disconnecting client...", message.eid)
					h.mu.Lock()
					if current, ok := h.clients[c.eid]; ok && current == c {
						close(c.send)
						delete(h.clients, c.eid)
					}
					h.mu.Unlock()
				}
			} else {
				log.Printf("Message receiver not found: %s", message.eid)
			}
		}
	}
}

func (h *Hub) getClient(eid string) (*Client, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	client, ok := h.clients[eid]
	return client, ok
}
