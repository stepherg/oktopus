package bridge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"net"
	"reflect"
	"strings"
	"sync"

	"time"

	"github.com/OktopUSP/oktopus/backend/services/mtp/ws-adapter/internal/config"
	"github.com/OktopUSP/oktopus/backend/services/mtp/ws-adapter/internal/usp/usp_msg"
	"github.com/OktopUSP/oktopus/backend/services/mtp/ws-adapter/internal/usp/usp_record"
	"github.com/gorilla/websocket"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"
)

const (
	NATS_WS_SUBJECT_PREFIX         = "ws.usp.v1."
	NATS_WS_ADAPTER_SUBJECT_PREFIX = "ws-adapter.usp.v1."
	DEVICE_SUBJECT_PREFIX          = "device.usp.v1."
	WS_CONNECTION_RETRY            = 10 * time.Second
	MTP_NAME                       = "ws"
	PRESENCE_REFRESH               = 15 * time.Second
)

const (
	OFFLINE = iota
	ONLINE
)

type msgAnswer struct {
	Code int
	Msg  any
}

type deviceStatus struct {
	Eid    string
	Status string
}

type (
	Publisher  func(string, []byte) error
	Subscriber func(string, func(*nats.Msg)) (*nats.Subscription, error)
)

type Bridge struct {
	Pub             Publisher
	Sub             Subscriber
	Ws              config.Ws
	NewDeviceQueue  map[string]string
	NewDevQMutex    *sync.Mutex
	kv              jetstream.KeyValue
	presence        jetstream.KeyValue
	presenceMu      sync.Mutex
	presenceCancels map[string]context.CancelFunc
	Ctx             context.Context
	subs            []*nats.Subscription
	subsMu          sync.Mutex
}

func NewBridge(p Publisher, s Subscriber, ctx context.Context, w config.Ws, kv jetstream.KeyValue, presence jetstream.KeyValue) *Bridge {
	return &Bridge{
		Pub:             p,
		Sub:             s,
		Ws:              w,
		Ctx:             ctx,
		kv:              kv,
		presence:        presence,
		presenceCancels: make(map[string]context.CancelFunc),
	}
}

func (b *Bridge) StartBridge(port string, tls bool) {

	go func(port string, tls bool) {
		for {
			url, err := b.urlBuild(tls, port)
			if err != nil {
				log.Printf("failed to build websocket URL: %v", err)
				time.Sleep(WS_CONNECTION_RETRY)
				continue
			}
			dialer := b.newDialer()
			wc, _, err := dialer.Dial(url, nil)
			if err != nil {
				log.Printf("Error to connect to %s, err: %s", url, err)
				time.Sleep(WS_CONNECTION_RETRY)
				continue
			}
			log.Println("Connected to WS endpoint--> ", url)
			go b.subscribe(wc)
			done := make(chan struct{})
			go func(wc *websocket.Conn) {
				defer close(done)
				for {
					msgType, wsMsg, err := wc.ReadMessage()
					if err != nil {
						log.Printf("websocket read error (will reconnect): %v", err)
						_ = wc.Close()
						break
					}
					if msgType == websocket.TextMessage {
						b.statusMsgHandler(wsMsg)
						continue
					}

					var record usp_record.Record
					err = proto.Unmarshal(wsMsg, &record)
					if err != nil {
						log.Println(err)
					}
					device := record.FromId

					noSessionRecord := &usp_record.Record_NoSessionContext{
						NoSessionContext: &usp_record.NoSessionContextRecord{},
					}
					if reflect.TypeOf(record.RecordType) == reflect.TypeOf(noSessionRecord) {
						if _, ok := b.NewDeviceQueue[device]; ok {
							b.newDeviceMsgHandler(wc, device, wsMsg)
							continue
						}
						log.Println("Handle api request")
						var msg usp_msg.Msg
						err = proto.Unmarshal(record.GetNoSessionContext().Payload, &msg)
						if err != nil {
							log.Println(err)
							continue
						}
						b.Pub(DEVICE_SUBJECT_PREFIX+device+".api", wsMsg) //nolint:errcheck
						continue
					}

				}
			}(wc)
			// Block until the read goroutine exits, then retry after a short delay.
			<-done
			time.Sleep(WS_CONNECTION_RETRY)
		}
	}(port, tls)
}

func (b *Bridge) subscribe(wc *websocket.Conn) {

	// Drain any subscriptions from a previous connection.
	b.subsMu.Lock()
	for _, s := range b.subs {
		s.Drain() //nolint:errcheck
	}
	b.subs = nil
	b.subsMu.Unlock()

	// Cancel all active presence goroutines; keys will expire via TTL which
	// causes the adapter service watcher to mark those devices offline.
	b.stopAllPresence()

	addSub := func(subject string, handler func(*nats.Msg)) {
		sub, err := b.Sub(subject, handler)
		if err != nil {
			log.Printf("subscribe error on %s: %v", subject, err)
			return
		}
		b.subsMu.Lock()
		b.subs = append(b.subs, sub)
		b.subsMu.Unlock()
	}

	b.NewDeviceQueue = make(map[string]string)
	b.NewDevQMutex = &sync.Mutex{}

	addSub(NATS_WS_ADAPTER_SUBJECT_PREFIX+"*.info", func(msg *nats.Msg) {

		log.Printf("Received message on info subject")

		subj := strings.Split(msg.Subject, ".")
		device := subj[len(subj)-2]

		b.NewDevQMutex.Lock()
		b.NewDeviceQueue[device] = ""
		b.NewDevQMutex.Unlock()

		err := wc.WriteMessage(websocket.BinaryMessage, msg.Data)
		if err != nil {
			log.Printf("send websocket msg error: %q", err)
			return
		}
	})

	addSub(NATS_WS_ADAPTER_SUBJECT_PREFIX+"*.api", func(msg *nats.Msg) {

		log.Printf("Received message on api subject")

		err := wc.WriteMessage(websocket.BinaryMessage, msg.Data)
		if err != nil {
			log.Printf("send websocket msg error: %q", err)
			return
		}
	})

	addSub(NATS_WS_ADAPTER_SUBJECT_PREFIX+"rtt", func(msg *nats.Msg) {

		log.Printf("Received message on rtt subject")

		conn, err := net.Dial("tcp", b.Ws.Addr+b.Ws.Port)
		if err != nil {
			respondMsg(msg.Respond, 500, err.Error())
			return
		}
		defer func() { _ = conn.Close() }()

		rttMicros, err := getRTTMicros(conn.(*net.TCPConn))
		if err != nil {
			respondMsg(msg.Respond, 500, err.Error())
			return
		}
		rtt := time.Duration(rttMicros) * time.Microsecond

		respondMsg(msg.Respond, 200, rtt/1000)

	})
}

func respondMsg(respond func(data []byte) error, code int, msgData any) {

	msg, err := json.Marshal(msgAnswer{
		Code: code,
		Msg:  msgData,
	})
	if err != nil {
		log.Printf("Failed to marshal message: %q", err)
		_ = respond([]byte(err.Error()))
		return
	}

	_ = respond([]byte(msg))
}

func (b *Bridge) newDeviceMsgHandler(_ *websocket.Conn, device string, msg []byte) {
	log.Printf("New device %s response", device)

	// A USP agent may send NOTIFY or other Request-type messages before (or
	// interleaved with) the GetResponse triggered by deviceOnline.  Only treat
	// the message as the info response when it is actually a Body_Response;
	// otherwise forward it as a normal API message and keep the device in the
	// queue so the real GetResponse is still captured.
	var record usp_record.Record
	if err := proto.Unmarshal(msg, &record); err == nil {
		var message usp_msg.Msg
		if err := proto.Unmarshal(record.GetNoSessionContext().Payload, &message); err == nil {
			if _, isResponse := message.Body.MsgBody.(*usp_msg.Body_Response); !isResponse {
				log.Printf("Device %s sent non-response message during info phase, routing as API", device)
				b.Pub(DEVICE_SUBJECT_PREFIX+device+".api", msg) //nolint:errcheck
				return
			}
		}
	}

	b.Pub(NATS_WS_SUBJECT_PREFIX+device+".info", msg) //nolint:errcheck

	b.NewDevQMutex.Lock()
	delete(b.NewDeviceQueue, device)
	b.NewDevQMutex.Unlock()
}

func (b *Bridge) statusMsgHandler(wsMsg []byte) {
	var deviceStatus deviceStatus
	err := json.Unmarshal(wsMsg, &deviceStatus)
	if err != nil {
		log.Println("Websockets Text Message is not about devices status")
		return
	}
	b.Pub(NATS_WS_SUBJECT_PREFIX+deviceStatus.Eid+".status", []byte(deviceStatus.Status)) //nolint:errcheck

	if deviceStatus.Status == "1" {
		b.startPresence(deviceStatus.Eid)
	} else {
		b.stopPresence(deviceStatus.Eid)
	}
}

// sanitizeSN replaces characters that are not valid in NATS KV keys.
// Colons (used in USP EIDs, e.g. "os::D89C8E-...") are replaced with "=".
func sanitizeSN(sn string) string {
	return strings.ReplaceAll(sn, ":", "=")
}

func (b *Bridge) presenceKey(sn string) string {
	return MTP_NAME + "." + sanitizeSN(sn)
}

// startPresence starts a goroutine that refreshes the device's presence key
// every PRESENCE_REFRESH interval. Any existing goroutine for the same device
// is cancelled first.
func (b *Bridge) startPresence(sn string) {
	b.presenceMu.Lock()
	defer b.presenceMu.Unlock()

	if cancel, ok := b.presenceCancels[sn]; ok {
		cancel()
	}

	ctx, cancel := context.WithCancel(b.Ctx)
	b.presenceCancels[sn] = cancel

	key := b.presenceKey(sn)
	go func() {
		ticker := time.NewTicker(PRESENCE_REFRESH)
		defer ticker.Stop()
		if _, err := b.presence.Put(ctx, key, []byte("1")); err != nil {
			log.Printf("presence: initial put failed for %s: %v", sn, err)
		}
		for {
			select {
			case <-ticker.C:
				if _, err := b.presence.Put(ctx, key, []byte("1")); err != nil && ctx.Err() == nil {
					log.Printf("presence: refresh failed for %s: %v", sn, err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// stopPresence cancels the presence refresh goroutine for a device and
// immediately deletes its key so it shows offline without waiting for TTL.
func (b *Bridge) stopPresence(sn string) {
	b.presenceMu.Lock()
	defer b.presenceMu.Unlock()

	if cancel, ok := b.presenceCancels[sn]; ok {
		cancel()
		delete(b.presenceCancels, sn)
	}
	if err := b.presence.Delete(b.Ctx, b.presenceKey(sn)); err != nil {
		log.Printf("presence: delete failed for %s: %v", sn, err)
	}
}

// stopAllPresence cancels all presence refresh goroutines (called on reconnect).
// Keys are left to expire via TTL so the watcher fires offline events.
func (b *Bridge) stopAllPresence() {
	b.presenceMu.Lock()
	defer b.presenceMu.Unlock()

	for sn, cancel := range b.presenceCancels {
		cancel()
		delete(b.presenceCancels, sn)
	}
}

func (b *Bridge) urlBuild(tls bool, port string) (string, error) {
	prefix := "ws://"
	if tls {
		prefix = "wss://"
	}

	wsUrl := prefix + b.Ws.Addr + port + b.Ws.Route

	if b.Ws.AuthEnable {
		token, err := b.kv.Get(b.Ctx, "oktopusController")
		if err != nil {
			return "", err
		}
		wsUrl = wsUrl + "?token=" + string(token.Value())
	}

	return wsUrl, nil
}

func (b *Bridge) newDialer() websocket.Dialer {
	return websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: b.Ws.SkipTlsVerify,
		},
	}
}
