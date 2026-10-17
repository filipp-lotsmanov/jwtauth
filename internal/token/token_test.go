package token

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	vectorKey    = "learn-jwt-secret"
	vectorIssuer = "jwtauth-learning"

	vectorHeaderSeg    = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	vectorClaimsSeg    = "eyJzdWIiOiJ1c2VyLTQyIiwiaXNzIjoiand0YXV0aC1sZWFybmluZyIsImlhdCI6MTc2MDAwMDAwMCwiZXhwIjoxNzYwMDAzNjAwfQ"
	vectorSignatureSeg = "LklDdvTwibWFqiMutmXrg68gphiI1OANZOZpvvNW_a8"
)

func TestSignMatchesVector(t *testing.T) {
	s := &Signer{key: []byte(vectorKey), issuer: vectorIssuer}

	got, err := s.Sign(Claims{
		Subject:   "user-42",
		IssuedAt:  1760000000,
		ExpiresAt: 1760003600,
	})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	parts := strings.Split(got, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d segments, want 3 (token: %q)", len(parts), got)
	}

	if parts[0] != vectorHeaderSeg {
		t.Errorf("header segment:\n got  %s\n want %s", parts[0], vectorHeaderSeg)
	}
	if parts[1] != vectorClaimsSeg {
		t.Errorf("claims segment:\n got  %s\n want %s", parts[1], vectorClaimsSeg)
	}
	if parts[2] != vectorSignatureSeg {
		t.Errorf("signature segment:\n got  %s\n want %s", parts[2], vectorSignatureSeg)
	}
}

func TestSignOmitsUnsetTimeClaims(t *testing.T) {
	s := &Signer{key: []byte(vectorKey), issuer: vectorIssuer}

	got, err := s.Sign(Claims{Subject: "user-42"})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	parts := strings.Split(got, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d segments, want 3", len(parts))
	}

	const want = "eyJzdWIiOiJ1c2VyLTQyIiwiaXNzIjoiand0YXV0aC1sZWFybmluZyJ9"
	if parts[1] != want {
		t.Errorf("claims segment:\n got  %s\n want %s", parts[1], want)
	}
}

func TestSignOverwritesCallerIssuer(t *testing.T) {
	s := &Signer{key: []byte(vectorKey), issuer: vectorIssuer}

	got, err := s.Sign(Claims{
		Subject:   "user-42",
		Issuer:    "attacker-controlled",
		IssuedAt:  1760000000,
		ExpiresAt: 1760003600,
	})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	if parts := strings.Split(got, "."); parts[1] != vectorClaimsSeg {
		t.Errorf("caller-supplied issuer was not overwritten:\n got  %s\n want %s", parts[1], vectorClaimsSeg)
	}
}

func TestSignDoesNotMutateCallerClaims(t *testing.T) {
	s := &Signer{key: []byte(vectorKey), issuer: vectorIssuer}

	in := Claims{Subject: "user-42", ExpiresAt: 1760003600}
	if _, err := s.Sign(in); err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	if in.Issuer != "" {
		t.Errorf("Sign mutated the caller's Claims: Issuer is now %q", in.Issuer)
	}
}

func TestNewSignerRejectsShortKey(t *testing.T) {
	s, err := NewSigner(make([]byte, 31), vectorIssuer)
	if !errors.Is(err, ErrWeakKey) {
		t.Errorf("error: got %v, want ErrWeakKey", err)
	}
	if s != nil {
		t.Errorf("signer: got %v, want nil", s)
	}
}

func TestNewSignerRejectsEmptyIssuer(t *testing.T) {
	s, err := NewSigner(make([]byte, 32), "")
	if !errors.Is(err, ErrInvalidIssuer) {
		t.Errorf("error: got %v, want ErrInvalidIssuer", err)
	}
	if s != nil {
		t.Errorf("signer: got %v, want nil", s)
	}
}

func TestNewSignerAcceptsValidKey(t *testing.T) {
	s, err := NewSigner(make([]byte, 32), vectorIssuer)
	if err != nil {
		t.Fatalf("NewSigner returned error: %v", err)
	}
	if s == nil {
		t.Fatal("signer is nil")
	}
}

func TestNewSignerCopiesKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 1
	}

	s, err := NewSigner(key, vectorIssuer)
	if err != nil {
		t.Fatalf("NewSigner returned error: %v", err)
	}

	before, err := s.Sign(Claims{Subject: "user-42", ExpiresAt: 1760003600})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	for i := range key {
		key[i] = 2
	}

	after, err := s.Sign(Claims{Subject: "user-42", ExpiresAt: 1760003600})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	if before != after {
		t.Error("mutating the caller's key changed the signature; key was not copied")
	}
}

func TestNewSignerInstallsClock(t *testing.T) {
	s, err := NewSigner(make([]byte, 32), vectorIssuer)
	if err != nil {
		t.Fatalf("NewSigner returned error: %v", err)
	}
	if s.now == nil {
		t.Fatal("now is nil")
	}
	if got := s.now(); got.IsZero() {
		t.Error("clock returned the zero time")
	}
	_ = time.Now
}
