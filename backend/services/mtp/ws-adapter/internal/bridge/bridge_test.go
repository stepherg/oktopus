package bridge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWriteWSMessageSerializesConcurrentWrites(t *testing.T) {
	upgrader := websocket.Upgrader{}
	received := make(chan []byte, 32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade failed: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()

		for i := 0; i < 16; i++ {
			_, data, err := conn.ReadMessage()
			if err != nil {
				t.Errorf("read failed: %v", err)
				return
			}
			received <- data
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	b := &Bridge{NewDeviceQueue: make(map[string]string), NewDevQMutex: &sync.Mutex{}}

	var writers sync.WaitGroup
	for i := 0; i < 16; i++ {
		writers.Add(1)
		go func(i int) {
			defer writers.Done()
			if err := b.writeWSMessage(conn, websocket.TextMessage, []byte{byte(i)}); err != nil {
				t.Errorf("write failed: %v", err)
			}
		}(i)
	}
	writers.Wait()

	seen := make(map[byte]bool)
	deadline := time.After(time.Second)
	for len(seen) < 16 {
		select {
		case msg := <-received:
			if len(msg) != 1 {
				t.Fatalf("expected single-byte message, got %q", msg)
			}
			seen[msg[0]] = true
		case <-deadline:
			t.Fatalf("timed out waiting for websocket messages, received %d", len(seen))
		}
	}
}

func TestIsNewDeviceQueuedConcurrentAccess(t *testing.T) {
	b := &Bridge{NewDeviceQueue: make(map[string]string), NewDevQMutex: &sync.Mutex{}}
	b.NewDevQMutex.Lock()
	b.NewDeviceQueue["device"] = ""
	b.NewDevQMutex.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				b.NewDevQMutex.Lock()
				b.NewDeviceQueue["device"] = ""
				b.NewDevQMutex.Unlock()
				if !b.isNewDeviceQueued("device") {
					t.Error("expected device to be queued")
					return
				}
			}
		}()
	}
	wg.Wait()
}
