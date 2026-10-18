package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postRefresh(t *testing.T, h *Handler, c *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.Refresh(rec, req)
	return rec
}

func postLogout(t *testing.T, h *Handler, c *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.Logout(rec, req)
	return rec
}

func login(t *testing.T, h *Handler) (string, *http.Cookie) {
	t.Helper()

	rec := postLogin(t, h, fmt.Sprintf(`{"email":%q,"password":%q}`, testEmail, testPassword))
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status %d (body: %s)", rec.Code, rec.Body.String())
	}

	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("login: decode: %v", err)
	}

	c := refreshCookie(t, rec)
	if c == nil {
		t.Fatal("login: no refresh cookie")
	}
	return resp.AccessToken, c
}

func rotate(t *testing.T, h *Handler, c *http.Cookie) (string, *http.Cookie) {
	t.Helper()

	rec := postRefresh(t, h, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: status %d (body: %s)", rec.Code, rec.Body.String())
	}

	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("refresh: decode: %v", err)
	}

	next := refreshCookie(t, rec)
	if next == nil {
		t.Fatal("refresh: no refresh cookie")
	}
	return resp.AccessToken, next
}

func TestRefreshReturnsNewTokens(t *testing.T) {
	h, signer := newTestHandler(t)

	firstAccess, firstCookie := login(t, h)

	rec := postRefresh(t, h, firstCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("access_token is empty")
	}

	next := refreshCookie(t, rec)
	if next == nil {
		t.Fatal("no refresh cookie on the refresh response")
	}
	if next.Value == firstCookie.Value {
		t.Error("the same refresh token came back; rotation did not happen")
	}
	if !next.HttpOnly {
		t.Error("rotated refresh cookie is not HttpOnly")
	}

	claims, err := signer.Parse(resp.AccessToken)
	if err != nil {
		t.Fatalf("Parse refreshed access token: %v", err)
	}
	if claims.Subject != testUserID {
		t.Errorf("sub: got %q, want %q", claims.Subject, testUserID)
	}
	_ = firstAccess
}

func TestRefreshOldTokenIsDeadAfterRotation(t *testing.T) {
	h, _ := newTestHandler(t)

	_, first := login(t, h)
	if _, _ = rotate(t, h, first); false {
		return
	}

	rec := postRefresh(t, h, first)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("replay: got %d, want 401 (body: %s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Error("a replayed refresh token returned a new access token")
	}
}

func TestRefreshClearsCookieOnFailure(t *testing.T) {
	h, _ := newTestHandler(t)

	_, first := login(t, h)
	rotate(t, h, first)

	rec := postRefresh(t, h, first)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}

	c := refreshCookie(t, rec)
	if c == nil {
		t.Fatal("no Set-Cookie on a failed refresh; the browser keeps sending a dead token")
	}
	if c.MaxAge >= 0 {
		t.Errorf("MaxAge: got %d, want negative", c.MaxAge)
	}
	if c.Value != "" {
		t.Errorf("Value: got %q, want empty", c.Value)
	}
}

func TestRefreshReuseRevokesFamilyOverHTTP(t *testing.T) {
	h, _ := newTestHandler(t)

	_, r1 := login(t, h)
	_, r2 := rotate(t, h, r1)
	_, r3 := rotate(t, h, r2)

	if rec := postRefresh(t, h, r1); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay of r1: got %d, want 401", rec.Code)
	}

	if rec := postRefresh(t, h, r3); rec.Code != http.StatusUnauthorized {
		t.Errorf("r3 still works after family revocation: got %d", rec.Code)
	}
}

func TestRefreshRevocationDoesNotCrossSessions(t *testing.T) {
	h, _ := newTestHandler(t)

	_, sessionA := login(t, h)
	_, sessionB := login(t, h)

	rotate(t, h, sessionA)

	if rec := postRefresh(t, h, sessionA); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session A replay: got %d, want 401", rec.Code)
	}

	if rec := postRefresh(t, h, sessionB); rec.Code != http.StatusOK {
		t.Errorf("session B was revoked along with session A: got %d (body: %s)",
			rec.Code, rec.Body.String())
	}
}

func TestRefreshRejectsMissingCookie(t *testing.T) {
	h, _ := newTestHandler(t)

	rec := postRefresh(t, h, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
}

func TestRefreshRejectsUnknownToken(t *testing.T) {
	h, _ := newTestHandler(t)

	rec := postRefresh(t, h, &http.Cookie{Name: refreshCookieName, Value: "never-issued-by-anyone"})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
}

func TestRefreshIgnoresBody(t *testing.T) {
	h, _ := newTestHandler(t)

	_, c := login(t, h)

	body := fmt.Sprintf(`{"refresh_token":%q}`, c.Value)
	req := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Refresh(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a refresh token in the body was accepted: got %d", rec.Code)
	}
}

func TestLogoutKillsTheSession(t *testing.T) {
	h, _ := newTestHandler(t)

	_, c := login(t, h)

	rec := postLogout(t, h, c)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: got %d, want 204 (body: %s)", rec.Code, rec.Body.String())
	}

	if rec := postRefresh(t, h, c); rec.Code != http.StatusUnauthorized {
		t.Errorf("refresh after logout: got %d, want 401", rec.Code)
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	h, _ := newTestHandler(t)

	_, c := login(t, h)

	rec := postLogout(t, h, c)
	cleared := refreshCookie(t, rec)
	if cleared == nil {
		t.Fatal("logout did not clear the refresh cookie")
	}
	if cleared.MaxAge >= 0 {
		t.Errorf("MaxAge: got %d, want negative", cleared.MaxAge)
	}
	if cleared.Value != "" {
		t.Errorf("Value: got %q, want empty", cleared.Value)
	}
}

func TestLogoutKillsRotatedTokens(t *testing.T) {
	h, _ := newTestHandler(t)

	_, r1 := login(t, h)
	_, r2 := rotate(t, h, r1)

	if rec := postLogout(t, h, r2); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: got %d, want 204", rec.Code)
	}

	if rec := postRefresh(t, h, r2); rec.Code != http.StatusUnauthorized {
		t.Errorf("r2 still works after logout: got %d", rec.Code)
	}
}

func TestLogoutIsAlwaysNoContent(t *testing.T) {
	h, _ := newTestHandler(t)

	cases := []*http.Cookie{
		nil,
		{Name: refreshCookieName, Value: "never-issued"},
		{Name: refreshCookieName, Value: ""},
	}

	for i, c := range cases {
		rec := postLogout(t, h, c)
		if rec.Code != http.StatusNoContent {
			t.Errorf("case %d: got %d, want 204", i, rec.Code)
		}
	}
}
