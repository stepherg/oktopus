package events

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/OktopUSP/oktopus/backend/services/mtp/adapter/internal/events/cwmp_handler"
	"github.com/OktopUSP/oktopus/backend/services/mtp/adapter/internal/events/usp_handler"
	"github.com/OktopUSP/oktopus/backend/services/mtp/adapter/internal/nats"
	"github.com/nats-io/nats.go/jetstream"
)

func StartEventsListener(ctx context.Context, js jetstream.JetStream, uspHandler usp_handler.Handler, cwmpHandler cwmp_handler.Handler) {

	log.Println("Listening for nats events")

	uspEvents := []string{
		nats.MQTT_STREAM_NAME,
		nats.WS_STREAM_NAME,
		nats.STOMP_STREAM_NAME,
		nats.LORA_STREAM_NAME,
		nats.OPC_STREAM_NAME,
		nats.WEBPA_STREAM_NAME,
	}

	for _, uspEvent := range uspEvents {
		go func(event string) {
			for {
				consumer, err := js.Consumer(ctx, event, event)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("Failed to get consumer for %s: %v", event, err)
					time.Sleep(5 * time.Second)
					continue
				}
				messages, err := consumer.Messages()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("Failed to get consumer messages for %s: %v", event, err)
					time.Sleep(5 * time.Second)
					continue
				}

				for {
					msg, err := messages.Next()
					if err != nil {
						if ctx.Err() != nil {
							messages.Stop()
							return
						}
						log.Println("Error to get next message:", err)
						messages.Stop()
						time.Sleep(1 * time.Second)
						continue
					}

					data := msg.Data()

					log.Printf("Received message, subject: %s", msg.Subject())

					subject := strings.Split(msg.Subject(), ".")
					msgType := subject[len(subject)-1]
					device := subject[len(subject)-2]

					switch msgType {
					case "status":
						uspHandler.HandleDeviceStatus(device, msg.Subject(), data, event, func() { _ = msg.Ack() })
					case "info":
						uspHandler.HandleDeviceInfo(device, msg.Subject(), data, event, func() { _ = msg.Ack() })
					default:
						log.Printf("Unknown message type received, subject: %s", msg.Subject())
						_ = msg.Ack()
					}
				}
			}
		}(uspEvent)
	}

	cwmpEvents := []string{
		nats.CWMP_STREAM_NAME,
	}

	for _, cwmpEvent := range cwmpEvents {
		go func(event string) {
			for {
				consumer, err := js.Consumer(ctx, event, event)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("Failed to get consumer for %s: %v", event, err)
					time.Sleep(5 * time.Second)
					continue
				}
				messages, err := consumer.Messages()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("Failed to get consumer messages for %s: %v", event, err)
					time.Sleep(5 * time.Second)
					continue
				}

				for {
					msg, err := messages.Next()
					if err != nil {
						if ctx.Err() != nil {
							messages.Stop()
							return
						}
						log.Println("Error to get next message:", err)
						messages.Stop()
						time.Sleep(1 * time.Second)
						continue
					}

					data := msg.Data()

					log.Printf("Received message, subject: %s", msg.Subject())

					subject := strings.Split(msg.Subject(), ".")
					msgType := subject[len(subject)-1]
					device := subject[len(subject)-2]

					switch msgType {
					case "status":
						cwmpHandler.HandleDeviceStatus(device, msg.Subject(), data, func() { _ = msg.Ack() })
					case "info":
						cwmpHandler.HandleDeviceInfo(device, data, func() { _ = msg.Ack() })
					default:
						log.Printf("Unknown message type received, subject: %s", msg.Subject())
						_ = msg.Ack()
					}
				}
			}
		}(cwmpEvent)
	}
}
