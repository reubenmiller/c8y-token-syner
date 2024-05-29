package token

import (
	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	ExternalID string `json:"externalId"`
	jwt.RegisteredClaims
}

func Generate(claims Claims, signingKey []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	stoken, err := token.SignedString(signingKey)
	return stoken, err
}
