package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/leandrofars/oktopus/taas/internal/api"
	"github.com/leandrofars/oktopus/taas/internal/config"
	"github.com/leandrofars/oktopus/taas/internal/db"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
	"github.com/leandrofars/oktopus/taas/internal/testcases/section1"
	"github.com/leandrofars/oktopus/taas/internal/testcases/section11"
	"github.com/leandrofars/oktopus/taas/internal/testcases/section2"
	"github.com/leandrofars/oktopus/taas/internal/testcases/section3"
	"github.com/leandrofars/oktopus/taas/internal/testcases/section4"
	"github.com/leandrofars/oktopus/taas/internal/testcases/section6"
	"github.com/leandrofars/oktopus/taas/internal/testcases/section7"
)

func main() {
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	c := config.NewConfig()

	database := db.NewDatabase(c.Mongo.Ctx, c.Mongo.Uri)

	registry := testcases.NewRegistry()
	registry.Register(section1.All()...)
	registry.Register(section2.All()...)
	registry.Register(section3.All()...)
	registry.Register(section4.All()...)
	registry.Register(section6.All()...)
	registry.Register(section7.All()...)
	registry.Register(section11.All()...)

	a := api.NewApi(c, database, registry)
	a.StartApi()

	<-done
	log.Println("taas is shutting down...")
}
