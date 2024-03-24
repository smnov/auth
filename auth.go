package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	accessTokenMaxAge  = 10 * time.Minute
	refreshTokenMaxAge = time.Hour * 24
)

const (
	publicKey  = "public"
	privateKey = "private"
)

type TokenPair struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

type Token struct {
	UserID  string `bson:"_id"`
	Payload string `bson:"payload"`
}

func DecodeAccessToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(privateKey), nil
	})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(*jwt.MapClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	accountID, ok := (*claims)["account_id"].(string)
	if !ok {
		return "", fmt.Errorf("account_id not found or not a string")
	}

	return accountID, nil
}

func DecodeRefreshToken(encodedToken string) (string, error) {
	decodedToken, err := base64.StdEncoding.DecodeString(encodedToken)
	if err != nil {
		return "", err
	}
	separatorIndex := strings.Index(string(decodedToken), "lg$")

	if separatorIndex == -1 {
		return "", errors.New("random token separator not found")
	}

	id := string(decodedToken[:separatorIndex])
	return id, nil
}

func NewAccessToken(id string) (string, error) {
	expirationTime := time.Now().Add(time.Hour)
	accessClaims := &jwt.MapClaims{
		"account_id": id,
		"expires_at": expirationTime.Unix(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaims)

	return accessToken.SignedString([]byte(privateKey))
}

func NewRefreshToken(id string) (string, error) {
	tokenLength := 16

	token := make([]byte, tokenLength)

	if _, err := rand.Read(token); err != nil {
		return "", err
	}

	combinedToken := append([]byte(id), token...)

	refreshToken := base64.StdEncoding.EncodeToString(combinedToken)

	return refreshToken, nil
}

func NewTokenPair(userID string) (*TokenPair, error) {
	accessToken, err := NewAccessToken(userID)
	if err != nil {
		return nil, err
	}
	refreshToken, err := NewRefreshToken(userID)
	if err != nil {
		return nil, err
	}
	tokenPair := TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	return &tokenPair, nil
}
