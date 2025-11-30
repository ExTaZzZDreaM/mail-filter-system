package backendHandler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"mail_server/internal/service"
	"mail_server/models"
	"net"
	"net/http"
	"strings"
)

type BackendHandler struct {
	server  *http.Server
	service *service.Service
}

func NewBackendHandler(service *service.Service, addr string, tc *tls.Config) *BackendHandler {
	srv := &http.Server{
		Addr:      addr,
		TLSConfig: tc,
	}

	bh := &BackendHandler{
		server:  srv,
		service: service,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/register", bh.handleRegister)
	mux.HandleFunc("/auth", bh.handleAuth)
	mux.HandleFunc("/mails", bh.handleGetMails)
	mux.HandleFunc("/is_admin", bh.handleIsAdmin)
	mux.HandleFunc("/blocked-mails", bh.handleBlockedMails)
	mux.HandleFunc("/inactive", bh.handlerGetInactive)
	mux.HandleFunc("/update-status", bh.handlerUpdataStatusUser)

	bh.server.Handler = corsMiddleware(mux)
	return bh
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (bh *BackendHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := bh.service.Register(user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

func (bh *BackendHandler) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, err := bh.service.Auth(user)
	if err != nil {
		http.Error(w, fmt.Sprintf("Authentication failed: %s", err.Error()), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func (bh *BackendHandler) handleGetMails(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}
	token := parts[1]

	mails, err := bh.service.GetMail(token)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mails)
}

func (bh *BackendHandler) handleIsAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}
	token := parts[1]

	err := bh.service.IsAdmin(token)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (bh *BackendHandler) handleBlockedMails(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	token := parts[1]

	err := bh.service.IsAdmin(token)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	blMails := bh.service.GetBlockedMails()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(blMails)
}

func (bh *BackendHandler) handlerGetInactive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	token := parts[1]

	err := bh.service.IsAdmin(token)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	blUsers, err := bh.service.GetInactive()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")

	fmt.Println(blUsers)

	json.NewEncoder(w).Encode(blUsers)
}

func (bh *BackendHandler) handlerUpdataStatusUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}

	type req struct {
		Username string `json:"username"`
	}

	var asd req

	if err := json.NewDecoder(r.Body).Decode(&asd); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	token := parts[1]

	err := bh.service.IsAdmin(token)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err = bh.service.UpdateStatus(asd.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusOK)
}

func (s *BackendHandler) ListenAndServe() error {
	err := s.server.ListenAndServe()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return fmt.Errorf("listen and server: %w", err)
	}
	return nil
}

func (s *BackendHandler) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
