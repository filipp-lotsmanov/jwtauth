package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/filipp-lotsmanov/jwtauth/internal/token"
)

type spyHandler struct {
	called  bool
	subject string
	ok      bool
}

func (s *spyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.called = true
	s.subject, s.ok = SubjectFromContext(r.Context())
	w.WriteHeader(http.StatusOK)
}

func newTestSigner(t *testing.T) *token.Signer {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	s, err := token.NewSigner(key, testIssuer)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func newAuthedHandler(t *testing.T, signer *token.Signer) *Handler {
	t.Helper()
	h, err := NewHandler(NewUserStore(), NewRefreshStore(), signer, bcrypt.MinCost, 15*time.Minute,
		14*24*time.Hour, false)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

func validToken(t *testing.T, signer *token.Signer, sub string) string {
	t.Helper()
	now := time.Now()
	tok, err := signer.Sign(token.Claims{
		Subject:   sub,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(15 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return tok
}

func callRequireAuth(t *testing.T, h *Handler, authHeader string) (*httptest.ResponseRecorder, *spyHandler) {
	t.Helper()

	spy := &spyHandler{}
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()

	h.RequireAuth(spy).ServeHTTP(rec, req)
	return rec, spy
}

func TestRequireAuthAllowsValidToken(t *testing.T) {
	signer := newTestSigner(t)
	h := newAuthedHandler(t, signer)

	rec, spy := callRequireAuth(t, h, "Bearer "+validToken(t, signer, "u1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if !spy.called {
		t.Fatal("wrapped handler did not run")
	}
	if !spy.ok {
		t.Error("subject was not in the context")
	}
	if spy.subject != "u1" {
		t.Errorf("subject: got %q, want u1", spy.subject)
	}
}

func TestRequireAuthSchemeIsCaseInsensitive(t *testing.T) {
	signer := newTestSigner(t)
	h := newAuthedHandler(t, signer)
	tok := validToken(t, signer, "u1")

	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr"} {
		t.Run(scheme, func(t *testing.T) {
			rec, spy := callRequireAuth(t, h, scheme+" "+tok)
			if rec.Code != http.StatusOK {
				t.Errorf("status: got %d, want 200", rec.Code)
			}
			if !spy.called {
				t.Error("wrapped handler did not run")
			}
		})
	}
}

func TestRequireAuthRejects(t *testing.T) {
	signer := newTestSigner(t)
	h := newAuthedHandler(t, signer)

	otherSigner, err := token.NewSigner([]byte("a-completely-different-32-byte-k"), testIssuer)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	valid := validToken(t, signer, "u1")

	expiredTok, err := signer.Sign(token.Claims{
		Subject:   "u1",
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tests := []struct {
		name   string
		header string
	}{
		{"no header", ""},
		{"empty header value", " "},
		{"scheme only", "Bearer"},
		{"no scheme", valid},
		{"wrong scheme", "Basic " + valid},
		{"token is garbage", "Bearer notatoken"},
		{"token has two segments", "Bearer " + strings.Join(strings.Split(valid, ".")[:2], ".")},
		{"signed with another key", "Bearer " + validToken(t, otherSigner, "u1")},
		{"expired token", "Bearer " + expiredTok},
		{"empty token after scheme", "Bearer "},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, spy := callRequireAuth(t, h, tc.header)

			if spy.called {
				t.Error("AUTH BYPASS: wrapped handler ran despite rejection")
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status: got %d, want 401", rec.Code)
			}
		})
	}
}

func TestSubjectFromContextAbsent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/me", nil)

	sub, ok := SubjectFromContext(req.Context())
	if ok {
		t.Error("ok is true for a context that never went through RequireAuth")
	}
	if sub != "" {
		t.Errorf("subject: got %q, want empty", sub)
	}
}

func TestRequireAuthDoesNotMutateOriginalRequest(t *testing.T) {
	signer := newTestSigner(t)
	h := newAuthedHandler(t, signer)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+validToken(t, signer, "u1"))

	h.RequireAuth(&spyHandler{}).ServeHTTP(httptest.NewRecorder(), req)

	if _, ok := SubjectFromContext(req.Context()); ok {
		t.Error("the original request's context was mutated")
	}
}
