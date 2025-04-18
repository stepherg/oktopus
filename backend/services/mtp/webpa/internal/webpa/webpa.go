package webpa

import (
	"net/http"

	"github.com/OktopUSP/oktopus/webpa/internal/config"
	"github.com/OktopUSP/oktopus/webpa/internal/webpa/handler"
	"github.com/nats-io/nats.go/jetstream"
)

func StartNewServer(c config.Config, kv jetstream.KeyValue) {
	// Initialize handlers
	handler.InitHandlers(c)

	http.HandleFunc("/webpa/controller", func(w http.ResponseWriter, r *http.Request) {
		handler.ServeController(w, r, c.ControllerEID, kv)
	})

	handler.ServeAgent(c)
}
