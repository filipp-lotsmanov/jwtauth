package auth

import (
	"errors"
	"strings"
	"sync"
)

var ErrDuplicateUser = errors.New("auth: user already exists")

type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
}

type UserStore struct {
	mu    sync.RWMutex
	users map[string]User
}

func NewUserStore() *UserStore {
	return &UserStore{users: make(map[string]User)}
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func (s *UserStore) Add(user User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normalizeEmail(user.Email)
	if _, ok := s.users[key]; ok {
		return ErrDuplicateUser
	}
	user.Email = key
	s.users[key] = user
	return nil
}

func (s *UserStore) Get(email string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[normalizeEmail(email)]
	return user, ok
}
