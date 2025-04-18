// Loads environemnt variables and returns a config struct
package config

import (
	"context"
	"flag"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	Port          string // server port: e.g. ":8080"
	ControllerEID string // controller endpoint id
	Nats          Nats
	ArgusUrl      string
	HookHost      string
	HookPath      string
	HookUrl       string
	Bucket        string
	ScytaleUrl    string
	AuthHeader    string // Webpa authentication
	AllowedOrigin string
	Tls           bool
	TlsPort       string
	FullChain     string
	PrivateKey    string
}

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

func NewConfig() Config {

	//Defines log format
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	loadEnv()

	/*
		App variables priority:
		1º - Flag through command line.
		2º - Env variables.
		3º - Default flag value.
	*/

	/* ------------------------------ define flags ------------------------------ */
	natsUrl := flag.String("nats_url", lookupEnvOrString("NATS_URL", "nats://localhost:4222"), "url for nats server")
	natsName := flag.String("nats_name", lookupEnvOrString("NATS_NAME", "webpa-adapter"), "name for nats client")
	natsEnableTls := flag.Bool("nats_enable_tls", lookupEnvOrBool("NATS_ENABLE_TLS", false), "enbale TLS to nats server")
	clientCrt := flag.String("client_crt", lookupEnvOrString("CLIENT_CRT", "cert.pem"), "client certificate file to TLS connection")
	clientKey := flag.String("client_key", lookupEnvOrString("CLIENT_KEY", "key.pem"), "client key file to TLS connection")
	serverCA := flag.String("server_ca", lookupEnvOrString("SERVER_CA", "rootCA.pem"), "server CA file to TLS connection")
	flPort := flag.String("port", lookupEnvOrString("SERVER_PORT", ":8099"), "Server port")
	flControllerEid := flag.String("controller-eid", lookupEnvOrString("CONTROLLER_EID", "oktopusController"), "Controller eid")
	flArgusUrl := flag.String("argus_url", lookupEnvOrString("ARGUS_URL", "http://argus:6600"), "Argus URL")
	flHookHost := flag.String("hook-host", lookupEnvOrString("HOOK_HOST", "http://webpa"), "Hook hostname")
	flHookPath := flag.String("hook-path", lookupEnvOrString("HOOK_PATH", "/events"), "Hook Path")
	flBucket := flag.String("bucker", lookupEnvOrString("BUCKET", "webhooks"), "Bucket")
	flScytaleUrl := flag.String("scytale-url", lookupEnvOrString("SCYTALE_URL", "http://scytale:6300/api/v2/device"), "Scytale URL")
	flAuthHeader := flag.String("auth-header", lookupEnvOrString("AUTH_HEADER", "Basic dXNlcjpwYXNz"), "Webpa Authentication header")
	flAllowedOrigin := flag.String("allowed-origin", lookupEnvOrString("ALLOWED_ORIGIN", "webpa-adapter"), "Allowed Origin header")
	flTls := flag.Bool("tls", lookupEnvOrBool("SERVER_TLS_ENABLE", false), "Enable/disable websockets server tls")
	flTlsPort := flag.String("tls_port", lookupEnvOrString("SERVER_TLS_PORT", ":9099"), "Server Port to use if TLS is enabled")
	flFullchain := flag.String("fullchain_path", lookupEnvOrString("FULL_CHAIN_PATH", "cert.pem"), "Fullchain file path")
	flPrivKey := flag.String("privkey_path", lookupEnvOrString("PRIVATE_KEY_PATH", "key.pem"), "Private key file path")
	flHelp := flag.Bool("help", false, "Help")
	flag.Parse()
	/* -------------------------------------------------------------------------- */

	if *flHelp {
		flag.Usage()
		os.Exit(0)
	}

	ctx := context.TODO()

	return Config{
		Port:          *flPort,
		ControllerEID: *flControllerEid,
		ArgusUrl:      *flArgusUrl,
		HookPath:      *flHookPath,
		HookUrl:       *flHookHost + *flPort + *flHookPath,
		Bucket:        *flBucket,
		ScytaleUrl:    *flScytaleUrl,
		AuthHeader:    *flAuthHeader,
		Tls:           *flTls,
		TlsPort:       *flTlsPort,
		FullChain:     *flFullchain,
		PrivateKey:    *flPrivKey,
		AllowedOrigin: *flAllowedOrigin,
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
	}
}

// Load environment variables from .env or .env.local file
func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error to load environment variables:", err)
	}

	localEnv := ".env.local"
	if _, err := os.Stat(localEnv); err == nil {
		_ = godotenv.Overload(localEnv)
		log.Println("Loaded variables from '.env.local'")
	} else {
		log.Println("Loaded variables from '.env'")
	}
}

/* ---------------------------- helper functions ---------------------------- */
/*
	They are used to lookup if a environment variable is set with a value
	different of "" and return it.
	In case the var doesn't exist, it returns the default value.
	Also, they're useful to convert the string value of vars to the desired type.
*/

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

/* -------------------------------------------------------------------------- */
