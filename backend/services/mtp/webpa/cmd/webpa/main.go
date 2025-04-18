package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/OktopUSP/oktopus/webpa/internal/config"
	"github.com/OktopUSP/oktopus/webpa/internal/nats"
	"github.com/OktopUSP/oktopus/webpa/internal/webpa"
)

func main() {

	done := make(chan os.Signal, 1)

	conf := config.NewConfig()

	// Locks app running until it receives a stop command as Ctrl+C.
	signal.Notify(done, syscall.SIGINT)

	_, kv := nats.StartNatsClient(conf.Nats)

	webpa.StartNewServer(conf, kv)

	<-done

	log.Println("(⌐■_■) Websockets server is out!")
}
