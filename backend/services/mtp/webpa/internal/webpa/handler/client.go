package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/OktopUSP/oktopus/webpa/internal/config"
	"github.com/OktopUSP/oktopus/webpa/internal/usp_record"
	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/pkg/errors"
	"github.com/xmidt-org/ancla"
	"github.com/xmidt-org/argus/chrysom"
	"github.com/xmidt-org/wrp-go/v3"
	"google.golang.org/protobuf/proto"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 30 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 10 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512 * 1024

	retryInterval = 5 * time.Second
)

var (
	newline  = []byte{'\n'}
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return r.Header.Get("Origin") == conf.AllowedOrigin
		},
	}
	bufferPool = sync.Pool{
		New: func() any { return bytes.NewBuffer(make([]byte, 0, 4096)) },
	}
)

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub        *Hub
	eid        string          // Websockets client endpoint id, follows USP specification
	conn       *websocket.Conn // The websocket connection
	send       chan message    // Buffered channel of outbound messages
	httpClient *http.Client    // HTTP client for WebPA communication
	source     string          // WebPA device source (e.g., mac:1234)
}

// NewClient creates a new Client with a configured HTTP client.
func NewClient(hub *Hub, eid, source string) *Client {
	return &Client{
		hub:    hub,
		eid:    eid,
		source: source,
		send:   make(chan message, 100), // Buffered channel
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:    100,
				IdleConnTimeout: 135 * time.Second,
				MaxConnsPerHost: 10,
			},
		},
	}
}

// readPump pumps messages from the websocket connection to the hub.
func (c *Client) readPump(cEID string) {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket read error %v", err)
			}
			break
		}
		message := constructMsg(cEID, c.eid, data)
		c.hub.broadcast <- message
	}
}

// constructMsg creates a message from WebSocket data.
func constructMsg(eid, from string, data []byte) message {
	if eid == "" {
		var record usp_record.Record
		if err := proto.Unmarshal(data, &record); err != nil {
			log.Printf("Failed to unmarshal USP record %v", err)
		}
		eid = record.ToId
	}
	return message{
		eid:     eid,
		from:    from,
		data:    data,
		msgType: websocket.BinaryMessage,
	}
}

// writePump pumps messages from the hub to the websocket connection.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		close(c.send)
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				log.Printf("Hub closed channel for %v", c.eid)
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			w, err := c.conn.NextWriter(message.msgType)
			if err != nil {
				log.Printf("Failed to get writer %v", err)
				return
			}
			if _, err := w.Write(message.data); err != nil {
				log.Printf("Failed to write message %v", err)
			}
			n := len(c.send)
			for range n {
				if _, err := w.Write(newline); err != nil {
					log.Printf("Failed to write newline %v", err)
				}
				send := <-c.send
				if _, err := w.Write(send.data); err != nil {
					log.Printf("Failed to write queued message %v", err)
				}
			}
			if err := w.Close(); err != nil {
				log.Printf("Failed to close writer %v", err)
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("Failed to send ping %v", err)
				return
			}
		}
	}
}

// ServeController handles USP controller events via WebSocket.
func ServeController(w http.ResponseWriter, r *http.Request, cEID string, kv jetstream.KeyValue) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade WebSocket %v", err)
		return
	}
	client := NewClient(hub, cEID, "")
	client.conn = conn
	client.hub.register <- client
	go client.writePump()
	go client.readPump("")
}

// writePumpWebpa sends messages to devices via Scytale.
func (c *Client) writePumpWebpa() {

	for {
		message, ok := <-c.send
		if !ok {
			// The hub closed the channel.
			log.Println("The hub closed the channel of", c.eid)
			return
		}
		if err := c.sendToScytale(context.Background(), message); err != nil {
			log.Printf("sendToScytale() failed %v", err)
		}
	}
}

// sendToScytale sends a single message to Scytale with retries.
func (c *Client) sendToScytale(ctx context.Context, payload message) error {
	buf := bufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		bufferPool.Put(buf)
	}()
	wrpRequest := wrp.Message{
		Type:            wrp.SimpleRequestResponseMessageType,
		Source:          conf.ControllerEID,
		Destination:     fmt.Sprintf("%s/usp", c.source),
		ContentType:     wrp.MimeTypeOctetStream,
		TransactionUUID: uuid.New().String(),
		Path:            fmt.Sprintf("%d", payload.msgType),
		Payload:         payload.data,
	}
	if err := json.NewEncoder(buf).Encode(wrpRequest); err != nil {
		return errors.Wrap(err, "failed to encode WRP request")
	}
	postReq, err := http.NewRequestWithContext(ctx, "POST", conf.ScytaleUrl, buf)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}
	postReq.Header.Set("Content-Type", wrp.MimeTypeJson)
	postReq.Header.Set("Accept", wrp.MimeTypeJson)
	postReq.Header.Set("Authorization", conf.AuthHeader)
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 30 * time.Second
	var resp *http.Response
	err = backoff.Retry(func() error {
		var err error
		resp, err = c.httpClient.Do(postReq)
		if err != nil {
			return err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			return fmt.Errorf("invalid status code: %d", resp.StatusCode)
		}
		return nil
	}, b)
	if err != nil {
		return errors.Wrap(err, "failed to send to Scytale")
	}
	defer resp.Body.Close()
	return nil
}

// hookHandler processes agent webhook events.
func hookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Printf("Method not allowed %v", http.StatusMethodNotAllowed)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read request body %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	var record usp_record.Record
	if err := proto.Unmarshal(body, &record); err != nil {
		log.Printf("Failed to unmarshal body %v", err)
		http.Error(w, "Failed to unmarshal body", http.StatusBadRequest)
		return
	}
	if err := validateID(record.FromId); err != nil {
		log.Printf("Invalid FromId %v", err)
		http.Error(w, "Invalid FromId", http.StatusBadRequest)
		return
	}
	var disconnectMsg, connectMsg bool
	switch record.RecordType.(type) {
	case *usp_record.Record_Disconnect:
		disconnectMsg = true
	case *usp_record.Record_WebsocketConnect:
		connectMsg = true
	}
	if c, ok := hub.clients[record.FromId]; ok {
		if connectMsg {
			return // Skip redundant connect messages
		}
		if !disconnectMsg {
			message := constructMsg(record.ToId, record.FromId, body)
			c.hub.broadcast <- message
		} else {
			c.hub.unregister <- c
		}
	} else {
		if disconnectMsg {
			log.Printf("Received disconnect for non-existent client %v", record.FromId)
			return
		}
		source := extractSource(r.Header.Values("X-Xmidt-Metadata"))
		if source == "" {
			log.Printf("Mac address not found for device %v", record.FromId)
			http.Error(w, "Mac address not found", http.StatusBadRequest)
			return
		}
		client := NewClient(hub, record.FromId, source)
		client.hub.register <- client
		go client.writePumpWebpa()
	}
}

// extractSource extracts the mac address from metadata headers.
func extractSource(meta []string) string {
	for _, m := range meta {
		if strings.HasPrefix(m, "hw-mac=") {
			p := strings.Split(m, "=")
			return "mac:" + p[1]
		}
	}
	return ""
}

// validateID ensures the ID matches a safe format.
func validateID(id string) error {
	if !regexp.MustCompile(`^[a-zA-Z0-9-:.]+$`).MatchString(id) {
		return errors.New("invalid ID format")
	}
	return nil
}

// ServeAgent starts the HTTP server for agent hooks and registers the webhook.
func ServeAgent(c config.Config) {
	http.HandleFunc(c.HookPath, func(w http.ResponseWriter, r *http.Request) {
		hookHandler(w, r)
	})
	log.Printf("Starting server on port %v", c.Port)
	go func() {
		if c.Tls {
			if err := http.ListenAndServeTLS(c.TlsPort, c.FullChain, c.PrivateKey, nil); err != nil {
				log.Printf("Failed to start server %v", err)
			}
		} else {
			if err := http.ListenAndServe(c.Port, nil); err != nil {
				log.Printf("Failed to start server %v", err)
			}
		}
	}()

	go registerHook(c.HookUrl, []string{".*"}, 3)
}

// registerHook registers a webhook with Argus.
func registerHook(url string, event []string, retries int) {
	log.Printf("Registering webhook %v", url)
	config := ancla.Config{
		JWTParserType:     "simple",
		DisablePartnerIDs: true,
		BasicClientConfig: chrysom.BasicClientConfig{
			Address: conf.ArgusUrl,
			Bucket:  conf.Bucket,
			Auth: chrysom.Auth{
				Basic: conf.AuthHeader,
			},
		},
	}
	svc, err := ancla.NewService(config, nil)
	if err != nil {
		log.Printf("Webhook service initialization error %v", err)
		registerHookError(url, event, retries)
		return
	}
	hookDuration := time.Duration(0xffff) * time.Hour
	hookUntil := time.Now().Add(hookDuration)
	internalHook := ancla.InternalWebhook{
		Webhook: ancla.Webhook{
			Config: ancla.DeliveryConfig{
				URL:         url,
				ContentType: "application/json",
			},
			Events: event,
			Matcher: ancla.MetadataMatcherConfig{
				DeviceID: []string{".*"},
			},
			Duration: hookDuration,
			Until:    hookUntil,
		},
	}
	if err := svc.Add(context.TODO(), "", internalHook); err != nil {
		log.Printf("Error registering webhook %v", err)
		registerHookError(url, event, retries)
		return
	}
	log.Printf("Webhook registered successfully")
}

// registerHookError retries webhook registration on failure.
func registerHookError(url string, event []string, retries int) {
	if retries <= 0 {
		log.Printf("Max retries reached for webhook registration")
		return
	}
	log.Printf("Retrying webhook registration retries left %v", retries)
	time.AfterFunc(retryInterval, func() { registerHook(url, event, retries-1) })
}
