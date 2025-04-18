package nats

import (
	"log"
	"time"

	"github.com/leandrofars/oktopus/internal/config"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	NATS_ACCOUNT_SUBJ_PREFIX          = "account-manager.v1."
	NATS_REQUEST_TIMEOUT              = 10 * time.Second
	NATS_MQTT_SUBJECT_PREFIX          = "mqtt.usp.v1."
	NATS_MQTT_ADAPTER_SUBJECT_PREFIX  = "mqtt-adapter.usp.v1."
	NATS_ADAPTER_SUBJECT              = "adapter.usp.v1."
	NATS_WS_SUBJECT_PREFIX            = "ws.usp.v1."
	NATS_WS_ADAPTER_SUBJECT_PREFIX    = "ws-adapter.usp.v1."
	NATS_STOMP_ADAPTER_SUBJECT_PREFIX = "stomp-adapter.usp.v1."
	NATS_WEBPA_ADAPTER_SUBJECT_PREFIX = "webpa-adapter.usp.v1."
	DEVICE_SUBJECT_PREFIX             = "device.usp.v1."
	DEVICE_CWMP_SUBJECT_PREFIX        = "device.cwmp.v1."
	BUCKET_NAME                       = "devices-auth"
	BUCKET_DESCRIPTION                = "Devices authentication"
	NATS_CWMP_ADAPTER_SUBJECT_PREFIX  = "cwmp-adapter.v1."
)

func StartNatsClient(c config.Nats) (jetstream.JetStream, *nats.Conn, jetstream.KeyValue) {

	var (
		nc  *nats.Conn
		err error
	)

	opts := defineOptions(c)

	log.Printf("Connecting to NATS server %s", c.Url)

	for {
		nc, err = nats.Connect(c.Url, opts...)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}
	log.Printf("Successfully connected to NATS server %s", c.Url)

	js, err := jetstream.New(nc)
	if err != nil {
		log.Fatalf("Failed to create JetStream client: %v", err)
	}

	kv, err := js.CreateOrUpdateKeyValue(c.Ctx, jetstream.KeyValueConfig{
		Bucket:      BUCKET_NAME,
		Description: BUCKET_DESCRIPTION,
	})
	if err != nil {
		log.Fatalf("Failed to create KeyValue store: %v", err)
	}

	return js, nc, kv
}

func defineOptions(c config.Nats) []nats.Option {
	var opts []nats.Option

	opts = append(opts, nats.Name(c.Name))
	opts = append(opts, nats.MaxReconnects(-1))
	opts = append(opts, nats.ReconnectWait(5*time.Second))
	opts = append(opts, nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
		log.Printf("Got disconnected! Reason: %q\n", err)
	}))
	opts = append(opts, nats.ReconnectHandler(func(nc *nats.Conn) {
		log.Printf("Got reconnected to %v!\n", nc.ConnectedUrl())
	}))
	opts = append(opts, nats.ClosedHandler(func(nc *nats.Conn) {
		log.Printf("Connection closed. Reason: %q\n", nc.LastError())
	}))
	if c.EnableTls {
		log.Printf("Load certificates: %s and %s\n", c.Cert.CertFile, c.Cert.KeyFile)
		opts = append(opts, nats.RootCAs(c.Cert.CaFile))
		opts = append(opts, nats.ClientCert(c.Cert.CertFile, c.Cert.KeyFile))
	}

	return opts
}
