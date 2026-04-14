package auth

import (
	"fmt"
	"log"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

func getJwtKey() []byte {
	jwtKey, ok := os.LookupEnv("SECRET_API_KEY")
	if !ok || jwtKey == "" {
		return []byte("supersecretkey")
	}
	return []byte(jwtKey)
}

type JWTClaim struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	jwt.RegisteredClaims
}

// ValidateToken validates the same JWT tokens issued by the controller.
func ValidateToken(signedToken string) (email string, err error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&JWTClaim{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return getJwtKey(), nil
		},
	)
	if err != nil {
		log.Println(err)
		return
	}

	claims, ok := token.Claims.(*JWTClaim)
	if !ok || !token.Valid {
		err = fmt.Errorf("invalid token")
		return
	}
	email = claims.Email
	return
}
