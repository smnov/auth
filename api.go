package main

import (
	"encoding/json"
	"net/http"
)

func WriteJSON(w http.ResponseWriter, status int, v ...any) error {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func (s *APIServer) GetTokensHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	id := params.Get("id")

	if id == "" {
		WriteJSON(w, http.StatusBadRequest, "no id provided")
		return
	}

	refreshToken, err := NewRefreshToken()
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, err.Error())
		return

	}
	err = s.store.SaveRefreshToken(r.Context(), refreshToken)
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
	return
}

func (s *APIServer) RefreshTokensHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.Header.Get("refresh_token")
	accessToken := r.Header.Get("access_token")
	OldPair := TokenPair{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
	}
	newPairOfTokens, err := RefreshedTokens(OldPair)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, err)
		return
	}
	WriteJSON(w, http.StatusOK, newPairOfTokens)
}
