package main

import (
	"encoding/base64"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

const (
	accessTokenMaxAge  = 10 * time.Minute
	refreshTokenMaxAge = time.Hour
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
	refresh string
}

func NewAccessToken(id string) (string, error) {
	accessClaims := &jwt.MapClaims{
		"account_id": id,
		"expires_at": accessTokenMaxAge,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaims)

	return accessToken.SignedString([]byte(privateKey))
}

func NewRefreshToken() (string, error) {
	randomBytes := make([]byte, 32)
	refreshToken := base64.StdEncoding.EncodeToString(randomBytes)
	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedRefreshToken), nil
}

func RefreshedTokens(oldPair TokenPair) (*TokenPair, error) {
	id := "1"
	accessToken, err := NewAccessToken(id)
	if err != nil {
		return nil, err
	}
	refreshToken, err := NewRefreshToken()
	if err != nil {
		return nil, err
	}
	tokenPair := TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	return &tokenPair, nil
}
