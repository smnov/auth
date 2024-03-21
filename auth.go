package main

import (
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

const (
	accessTokenMaxAge  = 10 * time.Minute
	refreshTokenMaxAge = time.Hour
)

const (
	publicKey  = "public"
	privateKey = "private"
)

type Account struct {
	ID uuid.UUID
}

type AccessToken struct {
	AccountID uuid.UUID
	ExpiresAt int
}

type RefreshToken struct {
	AccountID uuid.UUID
	ExpiresAt int
}

func NewAccessToken(acc *Account) (string, error) {
	accessClaims := &jwt.MapClaims{
		"account_id": acc.ID,
		"expires_at": accessTokenMaxAge,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaims)

	return accessToken.SignedString([]byte(privateKey))

}

func NewRefreshToken() (string, error) {
	refreshClaims := &jwt.MapClaims{}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, refreshClaims)
	return refreshToken.SignedString([]byte(privateKey))
}

func UpdateToken() 

