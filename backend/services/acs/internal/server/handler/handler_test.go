package handler

import (
	"testing"
	"time"

	"github.com/oleiade/lane"
)

func TestCancelRequestAllowsConcurrentEnqueueAfterWaitingCleared(t *testing.T) {
	cpe := &CPE{
		SerialNumber: "device-1",
		Queue:        lane.NewQueue(),
		Waiting: &Request{
			Id:       "in-flight",
			Callback: make(chan []byte, 1),
		},
	}

	success := make(chan struct{})
	go func() {
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			ok, _ := cpe.TryEnqueueRequest(Request{Id: "next", Callback: make(chan []byte, 1)})
			if ok {
				close(success)
				return
			}
		}
	}()

	time.Sleep(20 * time.Millisecond)
	cpe.CancelRequest("in-flight")

	select {
	case <-success:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for enqueue after cancellation")
	}

	_, queueSize := cpe.SnapshotQueueState()
	if queueSize != 1 {
		t.Fatalf("expected queued follow-up request, got queue size %d", queueSize)
	}
}

func TestCancelRequestRemovesQueuedRequestByID(t *testing.T) {
	cpe := &CPE{
		SerialNumber: "device-2",
		Queue:        lane.NewQueue(),
	}

	queued, _ := cpe.TryEnqueueRequest(Request{Id: "queued", Callback: make(chan []byte, 1)})
	if !queued {
		t.Fatal("expected initial request to queue successfully")
	}

	cpe.CancelRequest("queued")

	_, queueSize := cpe.SnapshotQueueState()
	if queueSize != 0 {
		t.Fatalf("expected queued request to be removed, got queue size %d", queueSize)
	}
}
