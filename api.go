package main

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func writeJSON(w http.ResponseWriter, status int, v ...any) error {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func encryptToken(token string) (string, error) {
	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedRefreshToken), nil
}

func validateId(id string) (bool, error) {
	return regexp.Match("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$", []byte(id))
}

func validateRefreshToken(store Storage, ctx context.Context, refreshToken, userID string) error {
	hash, err := store.GetRefreshToken(ctx, refreshToken, userID)
	if err != nil {
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(refreshToken)); err != nil {
		return err
	}

	return nil
}

func (s *APIServer) GetTokensHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	id := params.Get("id")

	isValid, err := validateId(id)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	if !isValid {
		writeJSON(w, http.StatusBadRequest, "id is not valid uuid")
		return
	}

	timeNow := time.Now().Unix()
	refreshToken, err := NewRefreshToken(id, timeNow)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	hashedToken, err := encryptToken(refreshToken)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	err = s.store.SaveRefreshToken(r.Context(), hashedToken, id)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	accessToken, err := NewAccessToken(id, timeNow)
	if err != nil {
		writeJSON(w, http.StatusBadRequest)
		return
	}

	response := TokenPair{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *APIServer) RefreshTokensHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.Header.Get("refresh_token")
	accessToken := r.Header.Get("access_token")

	if refreshToken == "" || accessToken == "" {
		writeJSON(w, http.StatusBadRequest, "no tokens provided")
		return
	}

	userIDFromAccessToken, accessTime, err := DecodeAccessToken(accessToken)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	userIDFromRefreshToken, acaccessTimeFromRefresh, err := DecodeRefreshToken(refreshToken)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	if userIDFromAccessToken != userIDFromRefreshToken || accessTime != acaccessTimeFromRefresh {
		writeJSON(w, http.StatusBadRequest, "tokens doesn't match")
		return
	}
	if err := validateRefreshToken(s.store, r.Context(), refreshToken, userIDFromAccessToken); err != nil {
		writeJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	timeNow := time.Now().Unix()
	newRefreshToken, err := NewRefreshToken(userIDFromAccessToken, timeNow)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	hashedToken, err := encryptToken(newRefreshToken)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	err = s.store.ReplaceRefreshToken(r.Context(), hashedToken, userIDFromAccessToken)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	newAccessToken, err := NewAccessToken(userIDFromAccessToken, timeNow)
	if err != nil {
		writeJSON(w, http.StatusBadRequest)
		return
	}

	response := TokenPair{
		RefreshToken: newRefreshToken,
		AccessToken:  newAccessToken,
	}
	writeJSON(w, http.StatusOK, response)
}
