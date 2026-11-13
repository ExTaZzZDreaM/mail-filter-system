package backendService

import (
	"sync"
	"testing"
	"time"
)

func TestTokenStoreIssueLookup(t *testing.T) {
	ts := newTokenStore()
	tok := ts.issue("jdoe")
	if login, ok := ts.lookup(tok); !ok || login != "jdoe" {
		t.Fatalf("lookup = %q, %v; want jdoe, true", login, ok)
	}
	if _, ok := ts.lookup("unknown"); ok {
		t.Fatal("unknown token must not be found")
	}
}

func TestTokenStoreExpiry(t *testing.T) {
	ts := newTokenStore()
	tok := ts.issue("jdoe")
	ts.mu.Lock()
	s := ts.sessions[tok]
	s.expiresAt = time.Now().Add(-time.Second)
	ts.sessions[tok] = s
	ts.mu.Unlock()

	if _, ok := ts.lookup(tok); ok {
		t.Fatal("expired token must be rejected")
	}
}

func TestTokenStoreConcurrent(t *testing.T) {
	ts := newTokenStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok := ts.issue("u")
			ts.lookup(tok)
		}()
	}
	wg.Wait()
}
