package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"

	local "github.com/leandrofars/oktopus/internal/nats"
	"github.com/leandrofars/oktopus/internal/usp/usp_msg"
	"github.com/leandrofars/oktopus/internal/usp/usp_record"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const notifyInboxMaxPerDevice = 128

// notifyInbox is a thread-safe per-device ring-buffer of unsolicited Notify
// messages received from agents.
type notifyInbox struct {
	mu     sync.Mutex
	events map[string][]json.RawMessage // SN → queued events
}

func newNotifyInbox() *notifyInbox {
	return &notifyInbox{events: make(map[string][]json.RawMessage)}
}

func (ni *notifyInbox) push(sn string, raw json.RawMessage) {
	ni.mu.Lock()
	defer ni.mu.Unlock()
	q := ni.events[sn]
	if len(q) >= notifyInboxMaxPerDevice {
		q = q[1:] // drop oldest
	}
	ni.events[sn] = append(q, raw)
}

// drain returns all queued events for the device and clears the queue.
func (ni *notifyInbox) drain(sn string) []json.RawMessage {
	ni.mu.Lock()
	defer ni.mu.Unlock()
	q := ni.events[sn]
	delete(ni.events, sn)
	return q
}

// peek returns all queued events without clearing.
func (ni *notifyInbox) peek(sn string) []json.RawMessage {
	ni.mu.Lock()
	defer ni.mu.Unlock()
	q := ni.events[sn]
	if len(q) == 0 {
		return nil
	}
	cp := make([]json.RawMessage, len(q))
	copy(cp, q)
	return cp
}

// startNotifyListener subscribes to device.usp.v1.*.api and stores any
// agent-initiated Notify messages in the inbox.  It is safe to call from
// StartApi because NATS subscriptions are goroutine-safe.
func (a *Api) startNotifyListener() {
	subj := local.DEVICE_SUBJECT_PREFIX + "*.api"
	_, err := a.nc.Subscribe(subj, func(msg *nats.Msg) {
		// Parse USP Record
		var record usp_record.Record
		if err := proto.Unmarshal(msg.Data, &record); err != nil {
			log.Printf("[notify_inbox] failed to unmarshal USP Record on %s: %v", msg.Subject, err)
			return
		}
		// Parse USP Message
		var uspMsg usp_msg.Msg
		if err := proto.Unmarshal(record.GetNoSessionContext().GetPayload(), &uspMsg); err != nil {
			log.Printf("[notify_inbox] failed to unmarshal USP Msg on %s: %v", msg.Subject, err)
			return
		}
		// Only interested in agent-initiated Notify (Body_Request containing Request_Notify)
		req, ok := uspMsg.Body.GetMsgBody().(*usp_msg.Body_Request)
		if !ok {
			// This is a response message (ADD_RESP, SET_RESP, etc.) — not a notification.
			return
		}
		notif, ok := req.Request.GetReqType().(*usp_msg.Request_Notify)
		if !ok {
			log.Printf("[notify_inbox] received a non-Notify request on %s (type %T) – ignoring",
				msg.Subject, req.Request.GetReqType())
			return
		}

		// Extract device SN from subject: device.usp.v1.{SN}.api
		parts := strings.Split(msg.Subject, ".")
		if len(parts) < 5 {
			log.Printf("[notify_inbox] unexpected subject format: %s", msg.Subject)
			return
		}
		sn := parts[len(parts)-2]

		rawJSON, err := protojson.Marshal(notif.Notify)
		if err != nil {
			log.Printf("[notify_inbox] marshal notify for %s: %v", sn, err)
			return
		}

		log.Printf("[notify_inbox] Notify from %s: %s", sn, string(rawJSON))
		a.notifyInbox.push(sn, json.RawMessage(rawJSON))
	})
	if err != nil {
		log.Printf("[notify_inbox] subscribe error: %v", err)
	}
}

// deviceNotifyEvents handles GET /api/device/{sn}/notify-events.
// Query params:
//   - clear=true  → drain (return and delete) the queue; default is drain
//   - peek=true   → read without clearing
func (a *Api) deviceNotifyEvents(w http.ResponseWriter, r *http.Request) {
	sn := getSerialNumberFromRequest(r)

	var events []json.RawMessage
	if r.URL.Query().Get("peek") == "true" {
		events = a.notifyInbox.peek(sn)
	} else {
		events = a.notifyInbox.drain(sn)
	}
	if events == nil {
		events = []json.RawMessage{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events) //nolint:errcheck
}
