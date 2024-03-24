package main

import (
	"encoding/json"
	"net/http"
	"regexp"

	"golang.org/x/crypto/bcrypt"
)

func WriteJSON(w http.ResponseWriter, status int, v ...any) error {
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

func (s *APIServer) GetTokensHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	id := params.Get("id")

	isValid, err := validateId(id)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	if !isValid {
		WriteJSON(w, http.StatusBadRequest, "id is not valid")
		return

	}

	refreshToken, err := NewRefreshToken(id)
	if err != nil {

		WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	hashedToken, err := encryptToken(refreshToken)
	if err != nil {

		WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	err = s.store.SaveRefreshToken(r.Context(), hashedToken, id)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	accessToken, err := NewAccessToken(id)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest)
		return
	}

	response := TokenPair{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
	}
	WriteJSON(w, http.StatusOK, response)
}

func (s *APIServer) RefreshTokensHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.Header.Get("refresh_token")
	accessToken := r.Header.Get("access_token")

	if refreshToken == "" || accessToken == "" {
		WriteJSON(w, http.StatusBadRequest, "no tokens provided")
		return
	}

	userIDFromAccessToken, err := DecodeAccessToken(accessToken)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	userIDFromRefreshToken, err := DecodeRefreshToken(refreshToken)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	if userIDFromAccessToken != userIDFromRefreshToken {
		WriteJSON(w, http.StatusBadRequest, "tokens doesn't match")
		return
	}

	hash, err := s.store.GetRefreshToken(r.Context(), refreshToken, userIDFromAccessToken)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(refreshToken))
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	newPairOfTokens, err := NewTokenPair(userIDFromAccessToken)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, err)
		return
	}
	WriteJSON(w, http.StatusOK, newPairOfTokens)
}
