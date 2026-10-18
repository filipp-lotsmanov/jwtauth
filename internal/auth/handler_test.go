package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/filipp-lotsmanov/jwtauth/internal/token"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "code-author-is-incredible"
	testUserID   = "u1"
	testIssuer   = "jwtauth-test"
)

func newTestHandler(t *testing.T) (*Handler, *token.Signer) {
	t.Helper()

	signer := newTestSigner(t)

	store := NewUserStore()
	hash, err := HashPassword(testPassword, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := store.Add(User{ID: testUserID, Email: testEmail, PasswordHash: hash}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	h, err := NewHandler(store, NewRefreshStore(), signer, bcrypt.MinCost, 15*time.Minute, 14*24*time.Hour, false)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h, signer
}

func postLogin(t *testing.T, h *Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	return rec
}

func refreshCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == refreshCookieName {
			return c
		}
	}
	return nil
}

func TestLoginSuccess(t *testing.T) {
	h, signer := newTestHandler(t)

	rec := postLogin(t, h, fmt.Sprintf(`{"email":%q,"password":%q}`, testEmail, testPassword))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rec.Body.String())
	}
	if resp.AccessToken == "" {
		t.Fatal("access_token is empty")
	}

	claims, err := signer.Parse(resp.AccessToken)
	if err != nil {
		t.Fatalf("Parse minted token: %v", err)
	}
	if claims.Subject != testUserID {
		t.Errorf("sub: got %q, want %q", claims.Subject, testUserID)
	}
	if claims.Issuer != testIssuer {
		t.Errorf("iss: got %q, want %q", claims.Issuer, testIssuer)
	}
	if claims.ExpiresAt <= claims.IssuedAt {
		t.Errorf("exp %d is not after iat %d", claims.ExpiresAt, claims.IssuedAt)
	}
}

func TestLoginSetsRefreshCookie(t *testing.T) {
	h, _ := newTestHandler(t)

	rec := postLogin(t, h, fmt.Sprintf(`{"email":%q,"password":%q}`, testEmail, testPassword))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}

	c := refreshCookie(t, rec)
	if c == nil {
		t.Fatal("no refresh_token cookie was set")
	}
	if c.Value == "" {
		t.Error("refresh cookie is empty")
	}
	if !c.HttpOnly {
		t.Error("refresh cookie is not HttpOnly; JavaScript can read the long-lived credential")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite: got %v, want Strict", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("Path: got %q, want /", c.Path)
	}
	if c.MaxAge <= 0 {
		t.Errorf("MaxAge: got %d, want positive", c.MaxAge)
	}
}

func TestLoginBodyHasNoRefreshToken(t *testing.T) {
	h, _ := newTestHandler(t)

	rec := postLogin(t, h, fmt.Sprintf(`{"email":%q,"password":%q}`, testEmail, testPassword))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}

	if strings.Contains(rec.Body.String(), "refresh_token") {
		t.Errorf("the refresh token is in the response body: %s", rec.Body.String())
	}

	c := refreshCookie(t, rec)
	if c != nil && strings.Contains(rec.Body.String(), c.Value) {
		t.Error("the refresh token value appears in the response body")
	}
}

func TestLoginSubjectIsNotEmail(t *testing.T) {
	h, signer := newTestHandler(t)

	rec := postLogin(t, h, fmt.Sprintf(`{"email":%q,"password":%q}`, testEmail, testPassword))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}

	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	claims, err := signer.Parse(resp.AccessToken)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if claims.Subject == testEmail {
		t.Error("sub is the email address; it must be the user ID")
	}
}

func TestLoginEmailIsCaseInsensitive(t *testing.T) {
	h, _ := newTestHandler(t)

	rec := postLogin(t, h, fmt.Sprintf(`{"email":"ALICE@Example.COM","password":%q}`, testPassword))
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	h, _ := newTestHandler(t)

	wrongPassword := postLogin(t, h, `{"email":"alice@example.com","password":"wrong"}`)
	unknownUser := postLogin(t, h, `{"email":"nobody@example.com","password":"wrong"}`)

	if wrongPassword.Code != http.StatusUnauthorized {
		t.Errorf("wrong password status: got %d, want 401", wrongPassword.Code)
	}
	if unknownUser.Code != http.StatusUnauthorized {
		t.Errorf("unknown user status: got %d, want 401", unknownUser.Code)
	}
	if wrongPassword.Body.String() != unknownUser.Body.String() {
		t.Errorf("response bodies differ:\n wrong password: %q\n unknown user:   %q",
			wrongPassword.Body.String(), unknownUser.Body.String())
	}
}

func TestLoginFailuresReturnNoToken(t *testing.T) {
	h, _ := newTestHandler(t)

	for _, body := range []string{
		`{"email":"alice@example.com","password":"wrong"}`,
		`{"email":"nobody@example.com","password":"wrong"}`,
		`{"email":"alice@example.com","password":""}`,
	} {
		rec := postLogin(t, h, body)
		if strings.Contains(rec.Body.String(), "access_token") {
			t.Errorf("body contains an access token for %s: %s", body, rec.Body.String())
		}
		if c := refreshCookie(t, rec); c != nil && c.Value != "" {
			t.Errorf("a refresh cookie was set on a failed login for %s", body)
		}
	}
}

func TestLoginRejectsBadRequests(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{"empty body", "", http.StatusBadRequest},
		{"not json", "notjson", http.StatusBadRequest},
		{"truncated json", `{"email":"a@b.c"`, http.StatusBadRequest},
		{"wrong types", `{"email":123,"password":true}`, http.StatusBadRequest},
		{"empty object", `{}`, http.StatusUnauthorized},
		{"missing password", `{"email":"alice@example.com"}`, http.StatusUnauthorized},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newTestHandler(t)
			rec := postLogin(t, h, tc.body)
			if rec.Code != tc.want {
				t.Errorf("status: got %d, want %d (body: %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestLoginRejectsOversizedBody(t *testing.T) {
	h, _ := newTestHandler(t)

	huge := `{"email":"alice@example.com","password":"` + strings.Repeat("a", maxLoginBodyBytes+1) + `"}`
	rec := postLogin(t, h, huge)

	if rec.Code == http.StatusOK {
		t.Error("oversized body was accepted")
	}
}

func TestMeThroughMiddleware(t *testing.T) {
	signer := newTestSigner(t)
	h := newAuthedHandler(t, signer)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+validToken(t, signer, "u1"))
	rec := httptest.NewRecorder()

	h.RequireAuth(http.HandlerFunc(h.Me)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	var resp meResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rec.Body.String())
	}
	if resp.MeID != "u1" {
		t.Errorf("user_id: got %q, want u1", resp.MeID)
	}
}

func TestMeResponseJSONKey(t *testing.T) {
	signer := newTestSigner(t)
	h := newAuthedHandler(t, signer)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+validToken(t, signer, "u1"))
	rec := httptest.NewRecorder()

	h.RequireAuth(http.HandlerFunc(h.Me)).ServeHTTP(rec, req)

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := raw["user_id"]; !ok {
		t.Errorf("response has no user_id key: %v", raw)
	}
}

func TestMeWithoutMiddleware(t *testing.T) {
	signer := newTestSigner(t)
	h := newAuthedHandler(t, signer)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	rec := httptest.NewRecorder()

	h.Me(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "user_id") {
		t.Errorf("body leaked a user_id despite no subject: %s", rec.Body.String())
	}
}

func TestMeIgnoresHeaderWithoutMiddleware(t *testing.T) {
	signer := newTestSigner(t)
	h := newAuthedHandler(t, signer)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+validToken(t, signer, "u1"))
	rec := httptest.NewRecorder()

	h.Me(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
}
