package handler

import (
	"encoding/json"
	"log"

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

// Controller Endpoint ID
var ceid string

func InitHandlers(eid string) {
	ceid = eid
	log.Println("New hub, Controller eid:", ceid)
	hub = newHub()
	hub.run()
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
			if existing, ok := h.clients[client.eid]; ok && existing != client {
				close(existing.send)
			}
			// register new eid
			h.clients[client.eid] = client
			if client.eid != ceid {
				log.Printf("New device connected: %s", client.eid)
				data, _ := json.Marshal(deviceStatus{client.eid, ONLINE})
				msg := message{
					from:    "WS server",
					eid:     ceid,
					data:    data,
					msgType: websocket.TextMessage,
				}
				log.Printf("%++v", msg)
				if c, ok := h.clients[msg.eid]; ok {
					select {
					// send message to receiver client
					case c.send <- msg:
						log.Printf("Sent a message %s --> %s", msg.from, msg.eid)
					default:
						// in case the msg sending fails, close the client connection
						// because it means that the client is no longer active
						log.Printf("Failed to send a msg to %s, disconnecting client...", msg.eid)
						close(c.send)
						delete(h.clients, c.eid)
					}
				}
			} else {
				log.Printf("New controller connected: %s", client.eid)
				// Replay ONLINE for all agents already connected so the controller
				// doesn't miss devices that connected before it did.
				for eid := range h.clients {
					if eid == ceid {
						continue
					}
					onlineData, _ := json.Marshal(deviceStatus{eid, ONLINE})
					replayMsg := message{
						from:    "WS server",
						eid:     ceid,
						data:    onlineData,
						msgType: websocket.TextMessage,
					}
					select {
					case client.send <- replayMsg:
						log.Printf("Replayed ONLINE for existing agent %s to reconnected controller", eid)
					default:
						log.Printf("Failed to replay ONLINE for %s (send buffer full)", eid)
					}
				}
			}

		case client := <-h.unregister:
			// verify if eid exists and still points at the disconnecting client
			if current, ok := h.clients[client.eid]; ok && current == client {
				// delete eid from map of connections
				delete(h.clients, client.eid)
				// close client messages receiving channel
				close(client.send)
			}
			log.Println("Disconnected client", client.eid)
			data, _ := json.Marshal(deviceStatus{client.eid, OFFLINE})
			msg := message{
				from:    "WS server",
				eid:     ceid,
				data:    data,
				msgType: websocket.TextMessage,
			}
			if c, ok := h.clients[msg.eid]; ok {
				select {
				// send message to receiver client
				case c.send <- msg:
					log.Printf("Sent a message %s --> %s", msg.from, msg.eid)
				default:
					// in case the msg sending fails, close the client connection
					// because it means that the client is no longer active
					log.Printf("Failed to send a msg to %s, disconnecting client...", msg.eid)
					close(c.send)
					delete(h.clients, c.eid)
				}
			}
		case message := <-h.broadcast:
			log.Println("send message to", message.eid)
			// verify if eid exists
			if c, ok := h.clients[message.eid]; ok {
				select {
				// send message to receiver client
				case c.send <- message:
					log.Printf("Sent a message %s --> %s", message.from, message.eid)
				default:
					// in case the message sending fails, close the client connection
					// because it means that the client is no longer active
					log.Printf("Failed to send a message to %s, disconnecting client...", message.eid)
					close(c.send)
					delete(h.clients, c.eid)
				}
			} else {
				log.Printf("Message receiver not found: %s", message.eid)
			}
		}
	}
}
