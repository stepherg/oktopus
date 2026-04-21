package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/OktopUSP/oktopus/ws/internal/config"
	"github.com/OktopUSP/oktopus/ws/internal/nats"
	"github.com/OktopUSP/oktopus/ws/internal/ws"
)

func main() {

	done := make(chan os.Signal, 1)

	conf := config.NewConfig()

	// Locks app running until it receives a stop command.
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	nc, kv := nats.StartNatsClient(conf.Nats)

	shutdown := ws.StartNewServer(conf, kv)

	<-done

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := shutdown(ctx); err != nil {
		log.Printf("failed to gracefully shut down websocket server: %v", err)
	}

	nc.Close()

	log.Println("(⌐■_■) Websockets server is out!")
}
