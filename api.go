package main

import (
	"fmt"
	"log"
	"net/http"
)

func (s *APIServer) GetRefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	token, err := s.store.GetRefreshToken(r.Context())
	params := r.URL.Query()
	id := params.Get("id")
	fmt.Println(id)
	if err != nil {
		log.Fatal("no refresh token in db")
	}
	fmt.Println(token)
}

func (s *APIServer) RefreshTokensHandler(w http.ResponseWriter, r *http.Request) {
}
