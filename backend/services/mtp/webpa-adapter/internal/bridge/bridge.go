package bridge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"

	"time"

	"github.com/OktopUSP/oktopus/backend/services/mtp/webpa-adapter/internal/config"
	"github.com/OktopUSP/oktopus/backend/services/mtp/webpa-adapter/internal/usp/usp_msg"
	"github.com/OktopUSP/oktopus/backend/services/mtp/webpa-adapter/internal/usp/usp_record"
	"github.com/gorilla/websocket"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const (
	NATS_WEBPA_SUBJECT_PREFIX         = "webpa.usp.v1."
	NATS_WEBPA_ADAPTER_SUBJECT_PREFIX = "webpa-adapter.usp.v1."
	DEVICE_SUBJECT_PREFIX             = "device.usp.v1."
	WEBPA_CONNECTION_RETRY            = 10 * time.Second
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
	Subscriber func(string, func(*nats.Msg)) error
)

type Bridge struct {
	Pub            Publisher
	Sub            Subscriber
	Ws             config.Ws
	NewDeviceQueue map[string]string
	NewDevQMutex   *sync.Mutex
	kv             jetstream.KeyValue
	Ctx            context.Context
}

func NewBridge(p Publisher, s Subscriber, ctx context.Context, w config.Ws, kv jetstream.KeyValue) *Bridge {
	return &Bridge{
		Pub: p,
		Sub: s,
		Ws:  w,
		Ctx: ctx,
		kv:  kv,
	}
}

func (b *Bridge) StartBridge(port string, tls bool) {

	go func(port string, tls bool) {
		for {
			url := b.urlBuild(tls, port)
			header := http.Header{}
			header.Set("Origin", "webpa-adapter")
			dialer := b.newDialer()
			wc, _, err := dialer.Dial(url, header)
			if err != nil {
				log.Printf("Error to connect to %s, err: %s", url, err)
				time.Sleep(WEBPA_CONNECTION_RETRY)
				continue
			}
			log.Println("Connected to Webpa endpoint--> ", url)
			go b.subscribe(wc)
			go func(wc *websocket.Conn) {
				for {
					msgType, wsMsg, err := wc.ReadMessage()
					if err != nil {
						if websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
							log.Printf("websocket error: %v", err)
							b.StartBridge(port, tls)
							return
						}
						log.Println("websocket unexpected error:", err)
						return
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
						b.Pub(DEVICE_SUBJECT_PREFIX+device+".api", wsMsg)
						continue
					}

				}
			}(wc)
			break
		}
	}(port, tls)
}

func (b *Bridge) subscribe(wc *websocket.Conn) {

	b.NewDeviceQueue = make(map[string]string)
	b.NewDevQMutex = &sync.Mutex{}

	b.Sub(NATS_WEBPA_ADAPTER_SUBJECT_PREFIX+"*.info", func(msg *nats.Msg) {

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

	b.Sub(NATS_WEBPA_ADAPTER_SUBJECT_PREFIX+"*.api", func(msg *nats.Msg) {

		log.Printf("Received message on api subject")

		err := wc.WriteMessage(websocket.BinaryMessage, msg.Data)
		if err != nil {
			log.Printf("send websocket msg error: %q", err)
			return
		}
	})

	b.Sub(NATS_WEBPA_ADAPTER_SUBJECT_PREFIX+"rtt", func(msg *nats.Msg) {

		log.Printf("Received message on rtt subject")

		conn, err := net.Dial("tcp", b.Ws.Addr+b.Ws.Port)
		if err != nil {
			respondMsg(msg.Respond, 500, err.Error())
			return
		}
		defer conn.Close()

		info, err := tcpInfo(conn.(*net.TCPConn))
		if err != nil {
			respondMsg(msg.Respond, 500, err.Error())
			return
		}
		rtt := time.Duration(info.Rtt) * time.Microsecond

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
		respond([]byte(err.Error()))
		return
	}

	respond([]byte(msg))
}

func (b *Bridge) newDeviceMsgHandler(wc *websocket.Conn, device string, msg []byte) {
	log.Printf("New device %s response", device)
	b.Pub(NATS_WEBPA_SUBJECT_PREFIX+device+".info", msg)

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
	b.Pub(NATS_WEBPA_SUBJECT_PREFIX+deviceStatus.Eid+".status", []byte(deviceStatus.Status))
}

func (b *Bridge) urlBuild(tls bool, port string) string {
	prefix := "ws://"
	if tls {
		prefix = "wss://"
	}

	wsUrl := prefix + b.Ws.Addr + port + b.Ws.Route

	token, _ := b.kv.Get(b.Ctx, "oktopusController")

	if b.Ws.AuthEnable {
		wsUrl = wsUrl + "?token=" + string(token.Value())
	}

	return wsUrl
}

func (b *Bridge) newDialer() websocket.Dialer {
	return websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: b.Ws.SkipTlsVerify,
		},
	}
}

func tcpInfo(conn *net.TCPConn) (*unix.TCPInfo, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var info *unix.TCPInfo
	ctrlErr := raw.Control(func(fd uintptr) {
		info, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	})
	switch {
	case ctrlErr != nil:
		return nil, ctrlErr
	case err != nil:
		return nil, err
	}
	return info, nil
}
