package main

import (
	"github.com/gorilla/mux"
)

type APIServer struct {
	ListenAddr string
	store      Storage
}

func (s *APIServer) Run() {
	router := mux.NewRouter()
	router.HandleFunc("/get", s.GetRefreshTokenHandler)
	router.HandleFunc("/refresh", s.RefreshTokensHandler)
}
