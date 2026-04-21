package bridge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/OktopUSP/oktopus/backend/services/mqtt-adapter/internal/config"
	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	OFFLINE = iota
	ONLINE
)

type msgAnswer struct {
	Code int
	Msg  any
}

const NATS_MQTT_SUBJECT_PREFIX = "mqtt.usp.v1."
const NATS_MQTT_ADAPTER_SUBJECT_PREFIX = "mqtt-adapter.usp.v1."
const DEVICE_SUBJECT_PREFIX = "device.usp.v1."
const MQTT_TOPIC_PREFIX = "oktopus/usp/"
const MTP_NAME = "mqtt"
const PRESENCE_REFRESH = 15 * time.Second

type (
	Publisher  func(string, []byte) error
	Subscriber func(string, func(*nats.Msg)) (*nats.Subscription, error)
)

type Bridge struct {
	Pub             Publisher
	Sub             Subscriber
	Mqtt            config.Mqtt
	kv              jetstream.KeyValue
	presence        jetstream.KeyValue
	presenceMu      sync.Mutex
	presenceCancels map[string]context.CancelFunc
	Ctx             context.Context
	subs            []*nats.Subscription
	subsMu          sync.Mutex
	connMu          sync.RWMutex
	connections     map[string]*autopaho.ConnectionManager
	activeConnID    string
	handlersOnce    sync.Once
}

func NewBridge(p Publisher, s Subscriber, ctx context.Context, m config.Mqtt, kv jetstream.KeyValue, presence jetstream.KeyValue) *Bridge {
	return &Bridge{
		Pub:             p,
		Sub:             s,
		Mqtt:            m,
		Ctx:             ctx,
		kv:              kv,
		presence:        presence,
		presenceCancels: make(map[string]context.CancelFunc),
		connections:     make(map[string]*autopaho.ConnectionManager),
	}
}

func (b *Bridge) StartBridge(serverUrl, clientId string) {
	connectionID := serverUrl + "|" + clientId

	broker, _ := url.Parse(serverUrl)

	status := make(chan *paho.Publish)
	controller := make(chan *paho.Publish)
	apiMsg := make(chan *paho.Publish)

	go b.mqttMessageHandler(status, controller, apiMsg)

	pahoClientConfig := buildClientConfig(status, controller, apiMsg, clientId, func() {
		b.clearActiveConnection(connectionID)
		b.stopAllPresence()
	})

	autopahoClientConfig := autopaho.ClientConfig{
		BrokerUrls: []*url.URL{
			broker,
		},
		KeepAlive:         30,
		ConnectRetryDelay: 5 * time.Second,
		ConnectTimeout:    5 * time.Second,
		OnConnectionUp: func(cm *autopaho.ConnectionManager, connAck *paho.Connack) {
			log.Printf("Connected to MQTT broker--> %s", serverUrl)
			b.setActiveConnection(connectionID, cm)
			if err := subscribe(b.Mqtt.Ctx, b.Mqtt.Qos, cm); err != nil {
				log.Printf("mqtt subscribe failed: %v", err)
			}
		},
		OnConnectError: func(err error) {
			log.Printf("Error while attempting connection: %s\n", err)
		},
		ClientConfig: *pahoClientConfig,
		TlsCfg: &tls.Config{
			InsecureSkipVerify: b.Mqtt.SkipVerify,
		},
	}

	b.setMqttPassword()
	if b.Mqtt.Username != "" && b.Mqtt.Password != "" {
		autopahoClientConfig.SetUsernamePassword(b.Mqtt.Username, []byte(b.Mqtt.Password)) //nolint:staticcheck
	}

	log.Println("MQTT client id:", pahoClientConfig.ClientID)
	log.Println("MQTT username:", b.Mqtt.Username)
	log.Println("MQTT password: [REDACTED]")

	_, err := autopaho.NewConnection(b.Ctx, autopahoClientConfig)
	if err != nil {
		log.Fatalln(err)
	}

	b.handlersOnce.Do(func() {
		b.natsMessageHandler()
	})
}

func (b *Bridge) natsMessageHandler() {
	addSub := func(subject string, handler func(*nats.Msg)) {
		sub, err := b.Sub(subject, handler)
		if err != nil {
			log.Printf("subscribe error on %s: %v", subject, err)
			return
		}
		b.subsMu.Lock()
		b.subs = append(b.subs, sub)
		b.subsMu.Unlock()
	}

	addSub(NATS_MQTT_ADAPTER_SUBJECT_PREFIX+"*.info", func(m *nats.Msg) {

		log.Printf("Received message on info subject")
		if err := b.publish(b.Ctx, &paho.Publish{
			QoS:     byte(b.Mqtt.Qos),
			Topic:   MQTT_TOPIC_PREFIX + "v1/agent/" + getDeviceFromSubject(m.Subject),
			Payload: m.Data,
			Properties: &paho.PublishProperties{
				ResponseTopic: "oktopus/usp/v1/controller/" + getDeviceFromSubject(m.Subject),
			},
		}); err != nil {
			log.Printf("mqtt publish failed: %v", err)
		}

	})

	addSub(NATS_MQTT_ADAPTER_SUBJECT_PREFIX+"*.api", func(m *nats.Msg) {

		log.Printf("Received message on api subject")
		if err := b.publish(b.Ctx, &paho.Publish{
			QoS:     byte(b.Mqtt.Qos),
			Topic:   MQTT_TOPIC_PREFIX + "v1/agent/" + getDeviceFromSubject(m.Subject),
			Payload: m.Data,
			Properties: &paho.PublishProperties{
				ResponseTopic: "oktopus/usp/v1/api/" + getDeviceFromSubject(m.Subject),
			},
		}); err != nil {
			log.Printf("mqtt publish failed: %v", err)
		}

	})

	addSub(NATS_MQTT_ADAPTER_SUBJECT_PREFIX+"rtt", func(msg *nats.Msg) {

		log.Printf("Received message on rtt subject")
		url := strings.Split(b.Mqtt.Url, "://")[1]
		conn, err := net.Dial("tcp", url)
		if err != nil {
			respondMsg(msg.Respond, 500, err.Error())
			return
		}
		defer func() { _ = conn.Close() }()

		rttMicros, err := getRTTMicros(conn.(*net.TCPConn))
		if err != nil {
			respondMsg(msg.Respond, 500, err.Error())
			return
		}
		rtt := time.Duration(rttMicros) * time.Microsecond

		respondMsg(msg.Respond, 200, rtt/1000)
	})
}

func getDeviceFromSubject(subject string) string {
	paths := strings.Split(subject, ".")
	device := paths[len(paths)-2]
	return device
}

func (b *Bridge) setActiveConnection(connectionID string, cm *autopaho.ConnectionManager) {
	b.connMu.Lock()
	defer b.connMu.Unlock()

	b.connections[connectionID] = cm
	b.activeConnID = connectionID
}

func (b *Bridge) currentConnection() *autopaho.ConnectionManager {
	b.connMu.RLock()
	defer b.connMu.RUnlock()

	if b.activeConnID != "" {
		if cm, ok := b.connections[b.activeConnID]; ok {
			return cm
		}
	}

	for _, cm := range b.connections {
		return cm
	}

	return nil
}

func (b *Bridge) clearActiveConnection(connectionID string) {
	b.connMu.Lock()
	defer b.connMu.Unlock()

	delete(b.connections, connectionID)
	if b.activeConnID == connectionID {
		b.activeConnID = ""
		for id := range b.connections {
			b.activeConnID = id
			break
		}
	}
}

func (b *Bridge) publish(ctx context.Context, msg *paho.Publish) error {
	cm := b.currentConnection()
	if cm == nil {
		return errors.New("no active mqtt connection")
	}

	_, err := cm.Publish(ctx, msg)
	return err
}

func (b *Bridge) mqttMessageHandler(status, controller, apiMsg chan *paho.Publish) {
	for {
		select {
		case d := <-status:
			device := getDeviceFromTopic(d.Topic)
			_ = b.Pub(NATS_MQTT_SUBJECT_PREFIX+device+".status", d.Payload)
			if string(d.Payload) == "1" {
				b.startPresence(device)
			} else {
				b.stopPresence(device)
			}
		case c := <-controller:
			device := getDeviceFromTopic(c.Topic)
			// Publish to the info subject so the controller's info request gets its response.
			_ = b.Pub(NATS_MQTT_SUBJECT_PREFIX+device+".info", c.Payload)
			// Also publish to the api subject so that agent-initiated Notify messages
			// (e.g. ValueChange) reach the controller's notify inbox.  Non-Notify
			// messages (GET_RESP etc.) are filtered out by the notify inbox itself.
			_ = b.Pub(DEVICE_SUBJECT_PREFIX+device+".api", c.Payload)
		case a := <-apiMsg:
			_ = b.Pub(DEVICE_SUBJECT_PREFIX+getDeviceFromTopic(a.Topic)+".api", a.Payload)
		}
	}
}

func getDeviceFromTopic(topic string) string {
	paths := strings.Split(topic, "/")
	device := paths[len(paths)-1]
	return device
}

func subscribe(ctx context.Context, qos int, c *autopaho.ConnectionManager) error {
	if _, err := c.Subscribe(ctx, &paho.Subscribe{
		Subscriptions: []paho.SubscribeOptions{
			{
				Topic: MQTT_TOPIC_PREFIX + "+/api/+",
				QoS:   byte(qos),
			},
			{
				Topic: MQTT_TOPIC_PREFIX + "+/controller/+",
				QoS:   byte(qos),
			},
			{
				Topic: MQTT_TOPIC_PREFIX + "+/status/+",
				QoS:   byte(qos),
			},
		},
	}); err != nil {
		return err
	}

	log.Printf("Subscribed to %s", MQTT_TOPIC_PREFIX+"+/controller/+")
	log.Printf("Subscribed to %s", MQTT_TOPIC_PREFIX+"+/status/+")
	log.Printf("Subscribed to %s", MQTT_TOPIC_PREFIX+"+/api/+")
	return nil
}

func buildClientConfig(status, controller, apiMsg chan *paho.Publish, id string, onServerDisconnect func()) *paho.ClientConfig {
	log.Println("Starting new MQTT client")
	singleHandler := paho.NewSingleHandlerRouter(func(p *paho.Publish) { //nolint:staticcheck

		if strings.Contains(p.Topic, "status") {
			status <- p
		} else if strings.Contains(p.Topic, "controller") {
			controller <- p
		} else if strings.Contains(p.Topic, "api") {
			apiMsg <- p
		} else {
			log.Println("No handler for topic: ", p.Topic)
		}

	})

	clientConfig := paho.ClientConfig{}

	clientConfig = paho.ClientConfig{
		Router: singleHandler,
		OnServerDisconnect: func(d *paho.Disconnect) {
			if d.Properties != nil {
				log.Printf("Requested disconnect: %s\n , properties reason: %s\n", clientConfig.ClientID, d.Properties.ReasonString)
			} else {
				log.Printf("Requested disconnect; %s reason code: %d\n", clientConfig.ClientID, d.ReasonCode)
			}
			if onServerDisconnect != nil {
				onServerDisconnect()
			}
		},
		OnClientError: func(err error) {
			log.Println(err)
		},
	}

	if id != "" {
		clientConfig.ClientID = id
	} else {
		clientConfig.ClientID = uuid.NewString()
	}

	return &clientConfig
}

func respondMsg(respond func(data []byte) error, code int, msgData any) {

	msg, err := json.Marshal(msgAnswer{
		Code: code,
		Msg:  msgData,
	})
	if err != nil {
		log.Printf("Failed to marshal message: %q", err)
		_ = respond([]byte(err.Error()))
		return
	}

	_ = respond([]byte(msg))
}

func (b *Bridge) setMqttPassword() {
	entry, err := b.kv.Get(b.Ctx, b.Mqtt.Username)
	if err != nil {
		log.Printf("Error getting key %s: %v", b.Mqtt.Username, err)
		return
	}

	b.Mqtt.Password = string(entry.Value())
}

func sanitizeSN(sn string) string {
	return strings.ReplaceAll(sn, ":", "=")
}

func (b *Bridge) presenceKey(sn string) string {
	return MTP_NAME + "." + sanitizeSN(sn)
}

func (b *Bridge) startPresence(sn string) {
	b.presenceMu.Lock()
	defer b.presenceMu.Unlock()

	if cancel, ok := b.presenceCancels[sn]; ok {
		cancel()
	}

	ctx, cancel := context.WithCancel(b.Ctx)
	b.presenceCancels[sn] = cancel

	key := b.presenceKey(sn)
	go func() {
		ticker := time.NewTicker(PRESENCE_REFRESH)
		defer ticker.Stop()
		if _, err := b.presence.Put(ctx, key, []byte("1")); err != nil {
			log.Printf("presence: initial put failed for %s: %v", sn, err)
		}
		for {
			select {
			case <-ticker.C:
				if _, err := b.presence.Put(ctx, key, []byte("1")); err != nil && ctx.Err() == nil {
					log.Printf("presence: refresh failed for %s: %v", sn, err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (b *Bridge) stopPresence(sn string) {
	b.presenceMu.Lock()
	defer b.presenceMu.Unlock()

	if cancel, ok := b.presenceCancels[sn]; ok {
		cancel()
		delete(b.presenceCancels, sn)
	}
	if err := b.presence.Delete(b.Ctx, b.presenceKey(sn)); err != nil {
		log.Printf("presence: delete failed for %s: %v", sn, err)
	}
}

func (b *Bridge) stopAllPresence() {
	b.presenceMu.Lock()
	defer b.presenceMu.Unlock()

	for sn, cancel := range b.presenceCancels {
		cancel()
		delete(b.presenceCancels, sn)
	}
}
