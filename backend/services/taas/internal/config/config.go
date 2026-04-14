package config

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/joho/godotenv"
)

const localEnv = ".env.local"

type Mongo struct {
	Uri string
	Ctx context.Context
}

type RestApi struct {
	Port string
	Ctx  context.Context
}

type Config struct {
	RestApi RestApi
	Mongo   Mongo
}

func NewConfig() *Config {
	loadEnvVariables()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flApiPort := flag.String("api_port", lookupEnvOrString("TAAS_PORT", "8001"), "TaaS REST API port")
	mongoUri := flag.String("mongo_uri", lookupEnvOrString("MONGO_URI", "mongodb://localhost:27017"), "MongoDB URI")
	flHelp := flag.Bool("help", false, "Help")

	flag.Parse()

	if *flHelp {
		flag.Usage()
		os.Exit(0)
	}

	ctx := context.TODO()

	return &Config{
		RestApi: RestApi{
			Port: *flApiPort,
			Ctx:  ctx,
		},
		Mongo: Mongo{
			Uri: *mongoUri,
			Ctx: ctx,
		},
	}
}

func loadEnvVariables() {
	if err := godotenv.Load(localEnv); err != nil {
		godotenv.Load()
	}
}

func lookupEnvOrString(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}
