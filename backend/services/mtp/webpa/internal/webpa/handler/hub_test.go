package handler

import (
	"fmt"
	"sync"
	"testing"
	"time"

	webpaconfig "github.com/OktopUSP/oktopus/webpa/internal/config"
)

var testConfOnce sync.Once

func configureTestHub() {
	testConfOnce.Do(func() {
		conf = webpaconfig.Config{ControllerEID: "controller"}
	})
}

func TestHubConcurrentRegisterUnregisterAndLookup(t *testing.T) {
	configureTestHub()
	h := newHub()
	go h.run()

	lookupDone := make(chan struct{})
	lookupErr := make(chan error, 1)
	go func() {
		defer close(lookupDone)
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if client, ok := h.getClient("controller"); ok && client == nil {
				lookupErr <- fmt.Errorf("lookup returned nil client")
				return
			}
		}
	}()

	for i := 0; i < 200; i++ {
		client := &Client{hub: h, eid: "controller", send: make(chan message, 1)}
		h.register <- client

		deadline := time.Now().Add(200 * time.Millisecond)
		for {
			got, ok := h.getClient("controller")
			if ok && got == client {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("expected registered client to be visible, got ok=%v client=%p want=%p", ok, got, client)
			}
		}

		h.unregister <- client
	}

	select {
	case err := <-lookupErr:
		t.Fatal(err)
	case <-lookupDone:
	}
}

func TestHubRegisterReplacesOldClientAndClosesOldChannel(t *testing.T) {
	configureTestHub()
	h := newHub()
	go h.run()

	oldClient := &Client{hub: h, eid: "controller", send: make(chan message, 1)}
	h.register <- oldClient

	newClient := &Client{hub: h, eid: "controller", send: make(chan message, 1)}
	h.register <- newClient

	select {
	case _, ok := <-oldClient.send:
		if ok {
			t.Fatal("expected replaced client channel to be closed")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for replaced client channel to close")
	}

	got, ok := h.getClient("controller")
	if !ok || got != newClient {
		t.Fatalf("expected replacement client to be active, got ok=%v client=%p want=%p", ok, got, newClient)
	}
}
