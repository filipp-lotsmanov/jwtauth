package token

import (
	"errors"
	"strings"
	"testing"
)

// Test vector: HS256, key "learn-jwt-secret" (16 bytes, below the
// NewSigner minimum, hence the direct struct literal).
const (
	vectorKey          = "learn-jwt-secret"
	vectorHeaderSeg    = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	vectorClaimsSeg    = "eyJzdWIiOiJ1c2VyLTQyIiwiaWF0IjoxNzYwMDAwMDAwLCJleHAiOjE3NjAwMDM2MDB9"
	vectorSignatureSeg = "1JfPBUdqCS0QdnkUjdkRQGBnOofvoDRxHb8siXjP9EM"
)

func TestSignMatchesVector(t *testing.T) {
	s := &Signer{key: []byte(vectorKey)}

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

func TestSignOmitsZeroClaims(t *testing.T) {
	s := &Signer{key: []byte(vectorKey)}

	got, err := s.Sign(Claims{Subject: "user-42"})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	parts := strings.Split(got, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d segments, want 3", len(parts))
	}

	// omitempty should drop iss, iat, exp and nbf entirely.
	const want = "eyJzdWIiOiJ1c2VyLTQyIn0"
	if parts[1] != want {
		t.Errorf("claims segment:\n got  %s\n want %s", parts[1], want)
	}
}

func TestNewSignerRejectsShortKey(t *testing.T) {
	s, err := NewSigner(make([]byte, 31))
	if !errors.Is(err, ErrWeakKey) {
		t.Errorf("error: got %v, want ErrWeakKey", err)
	}
	if s != nil {
		t.Errorf("signer: got %v, want nil", s)
	}
}

func TestNewSignerAcceptsValidKey(t *testing.T) {
	s, err := NewSigner(make([]byte, 32))
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

	s, err := NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner returned error: %v", err)
	}

	before, err := s.Sign(Claims{Subject: "user-42"})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	// Mutating the caller's slice must not affect the signer.
	for i := range key {
		key[i] = 2
	}

	after, err := s.Sign(Claims{Subject: "user-42"})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	if before != after {
		t.Error("mutating the caller's key changed the signature; key was not copied")
	}
}
