package backendService

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

const tokenTTL = 24 * time.Hour

type session struct {
	login     string
	expiresAt time.Time
}

// tokenStore is a thread-safe in-memory session store with expiry.
type tokenStore struct {
	mu       sync.RWMutex
	sessions map[string]session
}

func newTokenStore() *tokenStore {
	return &tokenStore{sessions: make(map[string]session)}
}

func (t *tokenStore) issue(login string) string {
	token := uuid.New().String()
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()
	// Drop expired sessions so the map does not grow without bound.
	for k, s := range t.sessions {
		if now.After(s.expiresAt) {
			delete(t.sessions, k)
		}
	}
	t.sessions[token] = session{login: login, expiresAt: now.Add(tokenTTL)}
	return token
}

func (t *tokenStore) lookup(token string) (string, bool) {
	t.mu.RLock()
	s, ok := t.sessions[token]
	t.mu.RUnlock()
	if !ok {
		return "", false
	}
	if time.Now().After(s.expiresAt) {
		t.mu.Lock()
		delete(t.sessions, token)
		t.mu.Unlock()
		return "", false
	}
	return s.login, true
}
