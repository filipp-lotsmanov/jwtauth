package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	ErrRefreshNotFound = errors.New("auth: refresh token not found")
	ErrRefreshExpired  = errors.New("auth: refresh token expired")
	ErrRefreshReused   = errors.New("auth: refresh token reused")
)

type RefreshRecord struct {
	UserID    string
	FamilyID  string
	ExpiresAt time.Time
	Consumed  bool
}

type RefreshStore struct {
	mu      sync.RWMutex
	records map[string]RefreshRecord
}

func NewRefreshStore() *RefreshStore {
	return &RefreshStore{records: make(map[string]RefreshRecord)}
}

func (r *RefreshStore) revokeFamilyLocked(FamilyID string) {
	for hash, record := range r.records {
		if record.FamilyID == FamilyID {
			record.Consumed = true
			delete(r.records, hash)
		}
	}
}

func (r *RefreshStore) RevokeFamily(FamilyID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revokeFamilyLocked(FamilyID)
}

func newRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newFamilyID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func (s *RefreshStore) Issue(userID, familyID string, ttl time.Duration) (string, error) {
	tok, err := newRefreshToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	hash := hashToken(tok)
	s.records[hash] = RefreshRecord{UserID: userID, FamilyID: familyID, ExpiresAt: time.Now().UTC().Add(ttl),
		Consumed: false}
	return tok, nil
}

func (s *RefreshStore) Consume(tok string) (RefreshRecord, error) {
	token := hashToken(tok)
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[token]
	switch {
	case !ok:
		return RefreshRecord{}, ErrRefreshNotFound
	case record.Consumed:
		s.revokeFamilyLocked(record.FamilyID)
		return RefreshRecord{}, ErrRefreshReused
	case time.Now().After(record.ExpiresAt):
		return RefreshRecord{}, ErrRefreshExpired
	default:
		record.Consumed = true
		s.records[token] = record
		return record, nil
	}
}
