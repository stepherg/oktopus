package cors

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/rs/cors"
)

func GetCorsConfig() cors.Cors {
	allowedOrigins := getCorsEnvConfig()
	log.Println("TaaS CORS - AllowedOrigins:", allowedOrigins)
	return *cors.New(cors.Options{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodOptions,
			http.MethodHead,
		},
		AllowedHeaders: []string{"*"},
	})
}

func getCorsEnvConfig() []string {
	val, _ := os.LookupEnv("TAAS_CORS")
	if val == "" {
		return []string{"*"}
	}
	return strings.Split(val, ",")
}
