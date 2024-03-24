package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/golang-jwt/jwt"
)

type TokenPair struct {
	RefreshToken string
	AccessToken  string
}

type Token struct {
	UserID  string `bson:"_id"`
	Payload string `bson:"payload"`
}

func DecodeAccessToken(tokenString string) (string, int64, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(privateKey), nil
	})
	if err != nil {
		return "", 0, err
	}

	if !token.Valid {
		return "", 0, fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", 0, fmt.Errorf("invalid token claims")
	}

	id, ok := claims["account_id"].(string)
	if !ok {
		return "", 0, fmt.Errorf("account_id not found in claims")
	}

	expirationTimeFloat64, ok := claims["expires_at"].(float64)
	if !ok {
		return "", 0, fmt.Errorf("expires_at not found in claims")
	}
	expirationTime := int64(expirationTimeFloat64)

	return id, expirationTime, nil
}

func DecodeRefreshToken(encodedToken string) (string, int64, error) {
	decodedToken, err := base64.StdEncoding.DecodeString(encodedToken)
	if err != nil {
		return "", 0, err
	}

	id := string(decodedToken[:36])
	timestampBytes := decodedToken[36:]
	timestamp := int64(binary.BigEndian.Uint64(timestampBytes))

	return id, timestamp, nil
}

func NewAccessToken(id string, expiresAt int64) (string, error) {
	accessClaims := &jwt.MapClaims{
		"account_id": id,
		"expires_at": expiresAt,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaims)

	return accessToken.SignedString([]byte(privateKey))
}

func NewRefreshToken(id string, accessTokenExpires int64) (string, error) {
	token := []byte(id)

	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, uint64(accessTokenExpires))
	tokenWithIdAndTime := append(token, bytes...)

	refreshToken := base64.StdEncoding.EncodeToString(tokenWithIdAndTime)

	return refreshToken, nil
}
