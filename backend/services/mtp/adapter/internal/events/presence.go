package events

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/OktopUSP/oktopus/backend/services/mtp/adapter/internal/db"
	"github.com/nats-io/nats.go/jetstream"
)

// parseMTPFromStreamName maps a JetStream stream name to a db.MTP value.
func parseMTPFromStreamName(name string) db.MTP {
	switch name {
	case "mqtt":
		return db.MQTT
	case "ws":
		return db.WEBSOCKETS
	case "stomp":
		return db.STOMP
	case "webpa":
		return db.WEBPA
	default:
		return db.UNDEFINED
	}
}

// StartPresenceWatcher watches the devices-presence KV bucket. When a key
// expires (TTL) or is deleted, it marks the corresponding device/MTP offline
// in MongoDB. Keys have the format "<mtp>.<sanitized-sn>" where colons in the
// SN are replaced with "=" signs.
func StartPresenceWatcher(ctx context.Context, presenceKV jetstream.KeyValue, database db.Database) {
	go func() {
		for {
			watcher, err := presenceKV.WatchAll(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("presence watcher: failed to start watcher: %v, retrying in 5s", err)
				time.Sleep(5 * time.Second)
				continue
			}

			log.Println("presence watcher: started")

			for entry := range watcher.Updates() {
				if entry == nil {
					// nil signals end of initial/historical values; live updates follow
					continue
				}

				op := entry.Operation()
				if op != jetstream.KeyValueDelete && op != jetstream.KeyValuePurge {
					continue
				}

				// Key format: "<mtp>.<sanitized-sn>"
				parts := strings.SplitN(entry.Key(), ".", 2)
				if len(parts) != 2 {
					log.Printf("presence watcher: unexpected key format %q, skipping", entry.Key())
					continue
				}

				mtpName := parts[0]
				sn := strings.ReplaceAll(parts[1], "=", ":")

				mtpLayer := parseMTPFromStreamName(mtpName)
				if mtpLayer == db.UNDEFINED {
					log.Printf("presence watcher: unknown MTP %q in key %q, skipping", mtpName, entry.Key())
					continue
				}

				log.Printf("presence: device %s (%s) expired, marking offline", sn, mtpName)
				if err := database.UpdateStatus(sn, db.Offline, mtpLayer); err != nil {
					log.Printf("presence watcher: UpdateStatus error for %s: %v", sn, err)
				}
			}

			if ctx.Err() != nil {
				return
			}
			log.Println("presence watcher: channel closed, restarting")
			time.Sleep(1 * time.Second)
		}
	}()
}
