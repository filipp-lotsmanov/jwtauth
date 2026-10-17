package auth

import (
	"errors"
	"sync"
	"testing"
)

func TestUserStoreRoundTrip(t *testing.T) {
	s := NewUserStore()

	in := User{ID: "u1", Email: "alice@example.com", PasswordHash: "hash"}
	if err := s.Add(in); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, ok := s.Get("alice@example.com")
	if !ok {
		t.Fatal("Get: user not found after Add")
	}
	if got != in {
		t.Errorf("user:\n got  %+v\n want %+v", got, in)
	}
}

func TestUserStoreGetMissing(t *testing.T) {
	s := NewUserStore()

	got, ok := s.Get("nobody@example.com")
	if ok {
		t.Error("Get: reported a user that was never added")
	}
	if got != (User{}) {
		t.Errorf("user: got %+v, want zero value", got)
	}
}

func TestUserStoreRejectsDuplicate(t *testing.T) {
	s := NewUserStore()

	u := User{ID: "u1", Email: "alice@example.com", PasswordHash: "hash"}
	if err := s.Add(u); err != nil {
		t.Fatalf("first Add: %v", err)
	}

	second := User{ID: "u2", Email: "alice@example.com", PasswordHash: "other"}
	if err := s.Add(second); !errors.Is(err, ErrDuplicateUser) {
		t.Errorf("second Add: got %v, want ErrDuplicateUser", err)
	}

	// The original must survive the rejected insert.
	got, ok := s.Get("alice@example.com")
	if !ok {
		t.Fatal("Get: original user disappeared")
	}
	if got.ID != "u1" {
		t.Errorf("ID: got %q, want u1", got.ID)
	}
}

func TestUserStoreNormalisesEmail(t *testing.T) {
	tests := []struct {
		name   string
		stored string
		lookup string
	}{
		{"stored mixed, looked up lower", "Alice@Example.com", "alice@example.com"},
		{"stored lower, looked up mixed", "alice@example.com", "ALICE@EXAMPLE.COM"},
		{"stored with spaces", "  alice@example.com  ", "alice@example.com"},
		{"looked up with spaces", "alice@example.com", "  alice@example.com  "},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewUserStore()
			if err := s.Add(User{ID: "u1", Email: tc.stored}); err != nil {
				t.Fatalf("Add: %v", err)
			}
			if _, ok := s.Get(tc.lookup); !ok {
				t.Errorf("stored %q, could not Get %q", tc.stored, tc.lookup)
			}
		})
	}
}

func TestUserStoreStoresNormalisedEmail(t *testing.T) {
	s := NewUserStore()
	if err := s.Add(User{ID: "u1", Email: "Alice@Example.com"}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, ok := s.Get("alice@example.com")
	if !ok {
		t.Fatal("Get: user not found")
	}
	if got.Email != "alice@example.com" {
		t.Errorf("stored email: got %q, want alice@example.com", got.Email)
	}
}

func TestUserStoreConcurrentAccess(t *testing.T) {
	s := NewUserStore()
	if err := s.Add(User{ID: "u1", Email: "alice@example.com"}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Get("alice@example.com")
		}()
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.Add(User{ID: "x", Email: string(rune('a'+n)) + "@example.com"})
		}(i)
	}
	wg.Wait()
}
