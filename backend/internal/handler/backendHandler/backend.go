package backendHandler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mail_server/internal/service"
	"mail_server/internal/service/backendService"
	"mail_server/models"
	"net"
	"net/http"
	"strings"
)

type BackendHandler struct {
	server  *http.Server
	service *service.Service
}

func NewBackendHandler(service *service.Service, addr string, tc *tls.Config, allowedOrigin string) *BackendHandler {
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
	mux.HandleFunc("/inactive", bh.handleGetInactive)
	mux.HandleFunc("/update-status", bh.handleUpdateUserStatus)

	bh.server.Handler = corsMiddleware(allowedOrigin, mux)
	return bh
}

func corsMiddleware(allowedOrigin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Vary", "Origin")
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"message": msg})
}

// bearerToken extracts the token from "Authorization: Bearer <token>".
func bearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header required")
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
		return "", errors.New("invalid Authorization header format")
	}
	return parts[1], nil
}

// requireMethod writes 405 and returns false if the request uses another method.
func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return false
	}
	return true
}

// requireAdmin writes an error response and returns false if the caller is not an admin.
func (bh *BackendHandler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	token, err := bearerToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return false
	}
	if err := bh.service.IsAdmin(token); err != nil {
		if errors.Is(err, backendService.ErrForbidden) {
			writeError(w, http.StatusForbidden, "Forbidden")
		} else {
			writeError(w, http.StatusUnauthorized, "Unauthorized")
		}
		return false
	}
	return true
}

func (bh *BackendHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	login, err := bh.service.Register(user)
	if err != nil {
		switch {
		case errors.Is(err, backendService.ErrUserExists):
			writeError(w, http.StatusConflict, "User with this name already exists")
		case errors.Is(err, models.ErrValidation):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			log.Printf("register: %v", err)
			writeError(w, http.StatusInternalServerError, "Registration failed")
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"message":  "User registered successfully, waiting for administrator approval",
		"username": login,
	})
}

func (bh *BackendHandler) handleAuth(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	token, err := bh.service.Auth(user)
	if err != nil {
		if errors.Is(err, backendService.ErrInactiveUser) {
			writeError(w, http.StatusForbidden, "Account is not activated yet")
			return
		}
		writeError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (bh *BackendHandler) handleGetMails(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	token, err := bearerToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	mails, err := bh.service.GetMail(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if mails == nil {
		mails = []models.Mail{}
	}

	writeJSON(w, http.StatusOK, mails)
}

func (bh *BackendHandler) handleIsAdmin(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) || !bh.requireAdmin(w, r) {
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (bh *BackendHandler) handleBlockedMails(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) || !bh.requireAdmin(w, r) {
		return
	}

	writeJSON(w, http.StatusOK, bh.service.GetBlockedMails())
}

func (bh *BackendHandler) handleGetInactive(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) || !bh.requireAdmin(w, r) {
		return
	}

	users, err := bh.service.GetInactive()
	if err != nil {
		log.Printf("get inactive users: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to load users")
		return
	}
	if users == nil {
		users = []models.User{}
	}

	writeJSON(w, http.StatusOK, users)
}

func (bh *BackendHandler) handleUpdateUserStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !bh.requireAdmin(w, r) {
		return
	}

	var body struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Username == "" {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := bh.service.UpdateStatus(body.Username); err != nil {
		if errors.Is(err, backendService.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "User not found")
			return
		}
		log.Printf("update status: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to update status")
		return
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
