package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

type APIServer struct {
	ListenAddr string
	store      Storage
}

func NewAPIServer(addr string, store Storage) *APIServer {
	return &APIServer{
		ListenAddr: addr,
		store:      store,
	}
}

func (s *APIServer) Run() {
	router := mux.NewRouter()
	router.HandleFunc("/get", s.GetTokensHandler)
	router.HandleFunc("/refresh", s.RefreshTokensHandler)
	fmt.Println("starting server on port:", s.ListenAddr)
	http.ListenAndServe(s.ListenAddr, router) // router is handler
}
