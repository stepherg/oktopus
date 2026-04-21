package ws

// Websockets server implementation inspired by https://github.com/gorilla/websocket/tree/main/examples/chat

import (
	"context"
	"log"
	"net/http"

	"github.com/OktopUSP/oktopus/ws/internal/config"
	"github.com/OktopUSP/oktopus/ws/internal/ws/handler"
	"github.com/gorilla/mux"
	"github.com/nats-io/nats.go/jetstream"
)

// Starts New Websockets Server
func StartNewServer(c config.Config, kv jetstream.KeyValue) func(context.Context) error {
	// Initialize handlers of websockets events
	handler.InitHandlers(c.ControllerEID)

	r := mux.NewRouter()
	r.HandleFunc("/ws/agent/{passwd}", func(w http.ResponseWriter, r *http.Request) {
		handler.ServeAgent(w, r, c.ControllerEID, kv, c.Auth)
	})
	r.HandleFunc("/ws/agent", func(w http.ResponseWriter, r *http.Request) {
		handler.ServeAgent(w, r, c.ControllerEID, kv, c.Auth)
	})
	r.HandleFunc("/ws/controller", func(w http.ResponseWriter, r *http.Request) {
		handler.ServeController(w, r, c.ControllerEID, c.Auth, kv)
	})

	var servers []*http.Server

	if c.Tls {
		tlsServer := &http.Server{Addr: c.TlsPort, Handler: r}
		servers = append(servers, tlsServer)
		go func() {
			log.Println("Websockets server running with TLS at port", c.TlsPort)
			err := tlsServer.ListenAndServeTLS(c.FullChain, c.PrivateKey)
			if err != nil && err != http.ErrServerClosed {
				log.Fatal("ListenAndServeTLS: ", err)
			}
		}()
	}

	if !c.NoTls {
		server := &http.Server{Addr: c.Port, Handler: r}
		servers = append(servers, server)
		go func() {
			log.Println("Websockets server running at port", c.Port)
			err := server.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				log.Fatal("ListenAndServe: ", err)
			}
		}()
	}

	return func(ctx context.Context) error {
		handler.Shutdown()

		var firstErr error
		for _, server := range servers {
			if err := server.Shutdown(ctx); err != nil && firstErr == nil {
				firstErr = err
			}
		}

		return firstErr
	}
}
