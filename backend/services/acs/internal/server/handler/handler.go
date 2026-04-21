package handler

import (
	"encoding/json"
	"oktopUSP/backend/services/acs/internal/config"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/oleiade/lane"
)

const Version = "1.0.0"

type Request struct {
	Id       string
	User     string
	Password string
	CwmpMsg  []byte
	Time     time.Time
	Callback chan []byte
}

type CPE struct {
	mu                   sync.Mutex
	SerialNumber         string
	Manufacturer         string
	OUI                  string
	ConnectionRequestURL string
	SoftwareVersion      string
	ExternalIPAddress    string
	Queue                *lane.Queue
	Waiting              *Request
	HardwareVersion      string
	LastConnection       time.Time
	DataModel            string
	Username             string
	Password             string
}

type Message struct {
	SerialNumber string
	Message      string
}

type WsMessage struct {
	Cmd string
}

type NatsSendMessage struct {
	MsgType string
	Data    json.RawMessage
}

type MsgCPEs struct {
	CPES map[string]*CPE
}

type Handler struct {
	pub       func(string, []byte) error
	sub       func(string, func(*nats.Msg)) error
	mu        sync.RWMutex
	Cpes      map[string]*CPE
	acsConfig config.Acs
}

const (
	NATS_CWMP_SUBJECT_PREFIX         = "cwmp.v1."
	NATS_CWMP_ADAPTER_SUBJECT_PREFIX = "cwmp-adapter.v1."
	NATS_ADAPTER_SUBJECT_PREFIX      = "adapter.v1."
)

func NewHandler(
	pub func(string, []byte) error,
	sub func(string, func(*nats.Msg)) error,
	cAcs config.Acs,
) *Handler {
	return &Handler{
		pub:       pub,
		sub:       sub,
		Cpes:      make(map[string]*CPE),
		acsConfig: cAcs,
	}
}

func (h *Handler) GetCPE(serialNumber string) (*CPE, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	cpe, ok := h.Cpes[serialNumber]
	return cpe, ok
}

func (h *Handler) PutCPE(cpe *CPE) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.Cpes[cpe.SerialNumber] = cpe
}

func (h *Handler) DeleteCPE(serialNumber string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.Cpes, serialNumber)
}

func (h *Handler) SnapshotCPEs() []*CPE {
	h.mu.RLock()
	defer h.mu.RUnlock()

	cpes := make([]*CPE, 0, len(h.Cpes))
	for _, cpe := range h.Cpes {
		cpes = append(cpes, cpe)
	}

	return cpes
}

func (c *CPE) TryEnqueueRequest(req Request) (bool, int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	queueSize := c.Queue.Size()
	if c.Waiting != nil || queueSize > 0 {
		return false, queueSize
	}

	c.Queue.Enqueue(req)
	return true, queueSize
}

func (c *CPE) CancelQueuedRequest() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.Waiting == nil && c.Queue.Size() > 0 {
		c.Queue.Dequeue()
	}
}

func (c *CPE) SnapshotQueueState() (string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.SerialNumber, c.Queue.Size()
}

func (c *CPE) ConnectionRequestDetails() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.SerialNumber, c.ConnectionRequestURL
}
