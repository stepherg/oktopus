package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/OktopUSP/oktopus/backend/services/mtp/webpa-adapter/internal/bridge"
	"github.com/OktopUSP/oktopus/backend/services/mtp/webpa-adapter/internal/config"
	"github.com/OktopUSP/oktopus/backend/services/mtp/webpa-adapter/internal/nats"
)

func main() {

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	c := config.NewConfig()

	kv, publisher, subscriber := nats.StartNatsClient(c.Nats)

	bridge := bridge.NewBridge(publisher, subscriber, c.Ws.Ctx, c.Ws, kv)

	if !c.Ws.NoTls {
		bridge.StartBridge(c.Ws.Port, false)
	}

	if c.Ws.TlsEnable {
		bridge.StartBridge(c.Ws.TlsPort, true)
	}

	<-done

	log.Println("webpa adapter is shutting down...")

}
