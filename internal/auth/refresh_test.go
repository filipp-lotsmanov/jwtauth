package auth

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testTTL      = 14 * 24 * time.Hour
	testFamilyID = "fam-1"
)

func mustIssue(t *testing.T, s *RefreshStore, userID, familyID string, ttl time.Duration) string {
	t.Helper()
	tok, err := s.Issue(userID, familyID, ttl)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok
}

func TestRefreshIssueAndConsume(t *testing.T) {
	s := NewRefreshStore()

	tok := mustIssue(t, s, "u1", testFamilyID, testTTL)

	rec, err := s.Consume(tok)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if rec.UserID != "u1" {
		t.Errorf("UserID: got %q, want u1", rec.UserID)
	}
	if rec.FamilyID != testFamilyID {
		t.Errorf("FamilyID: got %q, want %q", rec.FamilyID, testFamilyID)
	}
}

func TestRefreshStoresHashNotToken(t *testing.T) {
	s := NewRefreshStore()

	tok := mustIssue(t, s, "u1", testFamilyID, testTTL)

	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.records[tok]; ok {
		t.Error("the raw token is a key in the store; a store leak would hand over live credentials")
	}
	if _, ok := s.records[hashToken(tok)]; !ok {
		t.Error("the token hash is not a key in the store")
	}
}

func TestRefreshConsumeUnknown(t *testing.T) {
	s := NewRefreshStore()

	if _, err := s.Consume("never-issued"); !errors.Is(err, ErrRefreshNotFound) {
		t.Errorf("got %v, want ErrRefreshNotFound", err)
	}
}

func TestRefreshConsumeExpired(t *testing.T) {
	s := NewRefreshStore()

	tok := mustIssue(t, s, "u1", testFamilyID, -time.Second)

	if _, err := s.Consume(tok); !errors.Is(err, ErrRefreshExpired) {
		t.Errorf("got %v, want ErrRefreshExpired", err)
	}
}

func TestRefreshConsumeIsSingleUse(t *testing.T) {
	s := NewRefreshStore()

	tok := mustIssue(t, s, "u1", testFamilyID, testTTL)

	if _, err := s.Consume(tok); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if _, err := s.Consume(tok); err == nil {
		t.Fatal("second Consume succeeded; the token was never burned")
	}
}

func TestRefreshReuseRevokesWholeFamily(t *testing.T) {
	s := NewRefreshStore()

	r1 := mustIssue(t, s, "u1", testFamilyID, testTTL)

	rec, err := s.Consume(r1)
	if err != nil {
		t.Fatalf("consume r1: %v", err)
	}
	r2 := mustIssue(t, s, rec.UserID, rec.FamilyID, testTTL)

	rec, err = s.Consume(r2)
	if err != nil {
		t.Fatalf("consume r2: %v", err)
	}
	r3 := mustIssue(t, s, rec.UserID, rec.FamilyID, testTTL)

	if _, err := s.Consume(r1); !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("replay of r1: got %v, want ErrRefreshReused", err)
	}

	if _, err := s.Consume(r3); err == nil {
		t.Error("r3 still works after a family revocation")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	for hash, rec := range s.records {
		if rec.FamilyID == testFamilyID {
			t.Errorf("record %s survived family revocation", hash)
		}
	}
}

func TestRefreshRevokeFamilyIsScoped(t *testing.T) {
	s := NewRefreshStore()

	a := mustIssue(t, s, "u1", "fam-a", testTTL)
	b := mustIssue(t, s, "u1", "fam-b", testTTL)

	s.RevokeFamily("fam-a")

	if _, err := s.Consume(a); err == nil {
		t.Error("fam-a token still works after RevokeFamily")
	}
	if _, err := s.Consume(b); err != nil {
		t.Errorf("fam-b token was revoked too: %v", err)
	}
}

func TestRefreshRevokeFamilyUnknownIsNoop(t *testing.T) {
	s := NewRefreshStore()

	tok := mustIssue(t, s, "u1", testFamilyID, testTTL)
	s.RevokeFamily("no-such-family")

	if _, err := s.Consume(tok); err != nil {
		t.Errorf("revoking an unknown family affected an unrelated token: %v", err)
	}
}

func TestRefreshConcurrentConsumeAllowsOneWinner(t *testing.T) {
	for i := 0; i < 50; i++ {
		s := NewRefreshStore()
		tok := mustIssue(t, s, "u1", testFamilyID, testTTL)

		var wins atomic.Int32
		var wg sync.WaitGroup

		for g := 0; g < 2; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.Consume(tok); err == nil {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()

		if n := wins.Load(); n != 1 {
			t.Fatalf("iteration %d: %d goroutines consumed the same token, want exactly 1", i, n)
		}
	}
}

func TestRefreshConcurrentIssue(t *testing.T) {
	s := NewRefreshStore()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Issue("u1", testFamilyID, testTTL); err != nil {
				t.Errorf("Issue: %v", err)
			}
		}()
	}
	wg.Wait()

	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.records) != 100 {
		t.Errorf("records: got %d, want 100", len(s.records))
	}
}
