package bridge

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"oktopUSP/backend/services/acs/internal/config"
	"oktopUSP/backend/services/acs/internal/server/handler"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

type Bridge struct {
	pub  func(string, []byte) error
	sub  func(string, func(*nats.Msg)) error
	h    *handler.Handler
	conf *config.Acs
}

type msgAnswer struct {
	Code int
	Msg  any
}

func NewBridge(
	pub func(string, []byte) error,
	sub func(string, func(*nats.Msg)) error,
	h *handler.Handler,
	c *config.Acs,
) *Bridge {
	return &Bridge{
		pub:  pub,
		sub:  sub,
		h:    h,
		conf: c,
	}
}

func (b *Bridge) StartBridge() {

	_ = b.sub(handler.NATS_CWMP_ADAPTER_SUBJECT_PREFIX+"*.api", func(msg *nats.Msg) {
		if b.conf.DebugMode {
			log.Printf("Received message: %s", string(msg.Data))
			log.Printf("Subject: %s", msg.Subject)
			log.Printf("Reply: %s", msg.Reply)
		}

		device := getDeviceFromSubject(msg.Subject)
		cpe, ok := b.h.GetCPE(device)
		if !ok {
			log.Printf("Device %s not found", device)
			respondMsg(msg.Respond, http.StatusNotFound, "Device not found")
			return
		}

		request := handler.Request{
			Id:       uuid.NewString(),
			CwmpMsg:  msg.Data,
			Callback: make(chan []byte, 1),
			Time:     time.Now(),
		}

		enqueued, queueSize := cpe.TryEnqueueRequest(request)
		if !enqueued {
			serialNumber, currentQueueSize := cpe.SnapshotQueueState()
			log.Println("Queue size: ", queueSize)
			log.Printf("Current queue size for %s: %d", serialNumber, currentQueueSize)
			log.Printf("Device %s is busy", device)
			respondMsg(msg.Respond, http.StatusConflict, "Device is busy")
			return
		}

		err := b.h.ConnectionRequest(cpe)
		if err != nil {
			log.Println("Failed to do connection request", err)
			cpe.CancelRequest(request.Id)
			respondMsg(msg.Respond, http.StatusBadRequest, err.Error())
			return
		}

		select {
		case response := <-request.Callback:
			if b.conf.DebugMode {
				log.Printf("Received response from cpe: %s payload: %s ", cpe.SerialNumber, string(response))
			}
			respondMsg(msg.Respond, http.StatusOK, response)
		case <-time.After(b.conf.DeviceAnswerTimeout):
			log.Println("Device response timed out")
			cpe.CancelRequest(request.Id)
			respondMsg(msg.Respond, http.StatusRequestTimeout, "Request timeout")
		}

	})

	_ = b.sub(handler.NATS_CWMP_ADAPTER_SUBJECT_PREFIX+"rtt", func(msg *nats.Msg) {
		log.Printf("Received message on rtt subject")
		url := "127.0.0.1" + b.conf.Port
		conn, err := net.Dial("tcp", url)
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

	_ = respond(msg)
}

func getDeviceFromSubject(subject string) string {
	paths := strings.Split(subject, ".")
	device := paths[len(paths)-2]
	return device
}
