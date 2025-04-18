package config

import (
	"context"
	"flag"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

const LOCAL_ENV = ".env.local"

type Nats struct {
	Url       string
	Name      string
	EnableTls bool
	Cert      Tls
	Ctx       context.Context
}

type Tls struct {
	CertFile string
	KeyFile  string
	CaFile   string
}

type Ws struct {
	AuthEnable    bool
	Addr          string
	Port          string
	Route         string
	TlsEnable     bool
	TlsPort       string
	SkipTlsVerify bool
	NoTls         bool
	Ctx           context.Context
}

type Config struct {
	Nats Nats
	Ws   Ws
}

func NewConfig() *Config {
	loadEnvVariables()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	natsUrl := flag.String("nats_url", lookupEnvOrString("NATS_URL", "nats://oktopususer:oktopuspw@msg_broker:4222"), "url for nats server")
	natsName := flag.String("nats_name", lookupEnvOrString("NATS_NAME", "webpa-adapter"), "name for nats client")
	natsEnableTls := flag.Bool("nats_enable_tls", lookupEnvOrBool("NATS_ENABLE_TLS", true), "enbale TLS to nats server")
	clientCrt := flag.String("client_crt", lookupEnvOrString("CLIENT_CRT", "/tmp/nats/config/cert.pem"), "client certificate file to TLS connection")
	clientKey := flag.String("client_key", lookupEnvOrString("CLIENT_KEY", "/tmp/nats/config/key.pem"), "client key file to TLS connection")
	serverCA := flag.String("server_ca", lookupEnvOrString("SERVER_CA", "/tmp/nats/config/rootCA.pem"), "server CA file to TLS connection")
	wsAuthEnable := flag.Bool("ws_auth_enable", lookupEnvOrBool("WS_AUTH_ENABLE", false), "enable authentication for websocket server")
	wsAddr := flag.String("ws_addr", lookupEnvOrString("WS_ADDR", "webpa"), "webpa server address (domain or ip)")
	wsPort := flag.String("ws_port", lookupEnvOrString("WS_PORT", ":8099"), "webpa server port")
	wsTlsPort := flag.String("ws_tls_port", lookupEnvOrString("WS_TLS_PORT", ":8091"), "webpa tls server port")
	wsNoTls := flag.Bool("ws_no_tls", lookupEnvOrBool("WS_NO_TLS", false), "connects to webpa server without tls")
	wsRoute := flag.String("ws_route", lookupEnvOrString("WS_ROUTE", "/webpa/controller"), "webpa server route")
	wsTlsEnable := flag.Bool("ws_tls_enable", lookupEnvOrBool("WS_TLS_ENABLE", false), "access webpa via tls protocol (wss)")
	wsSkipTlsVerify := flag.Bool("ws_skip_tls_verify", lookupEnvOrBool("WS_SKIP_TLS_VERIFY", false), "skip tls verification for websocket server")
	flHelp := flag.Bool("help", false, "Help")

	flag.Parse()

	if *flHelp {
		flag.Usage()
		os.Exit(0)
	}

	if *wsNoTls && !*wsTlsEnable {
		log.Fatalf("You must configure at least one connection to the webpa server")
	}

	ctx := context.TODO()

	return &Config{
		Nats: Nats{
			Url:       *natsUrl,
			Name:      *natsName,
			EnableTls: *natsEnableTls,
			Ctx:       ctx,
			Cert: Tls{
				CertFile: *clientCrt,
				KeyFile:  *clientKey,
				CaFile:   *serverCA,
			},
		},
		Ws: Ws{
			AuthEnable:    *wsAuthEnable,
			Addr:          *wsAddr,
			Port:          *wsPort,
			Route:         *wsRoute,
			TlsEnable:     *wsTlsEnable,
			SkipTlsVerify: *wsSkipTlsVerify,
			Ctx:           ctx,
			TlsPort:       *wsTlsPort,
			NoTls:         *wsNoTls,
		},
	}
}

func loadEnvVariables() {
	err := godotenv.Load()

	if _, err := os.Stat(LOCAL_ENV); err == nil {
		_ = godotenv.Overload(LOCAL_ENV)
		log.Printf("Loaded variables from '%s'", LOCAL_ENV)
	}

	if err != nil {
		log.Println("Error to load environment variables:", err)
	} else {
		log.Println("Loaded variables from '.env'")
	}
}

func lookupEnvOrString(key string, defaultVal string) string {
	if val, _ := os.LookupEnv(key); val != "" {
		return val
	}
	return defaultVal
}

func lookupEnvOrBool(key string, defaultVal bool) bool {
	if val, _ := os.LookupEnv(key); val != "" {
		v, err := strconv.ParseBool(val)
		if err != nil {
			log.Fatalf("LookupEnvOrBool[%s]: %v", key, err)
		}
		return v
	}
	return defaultVal
}
