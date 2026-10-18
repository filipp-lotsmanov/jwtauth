package auth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/filipp-lotsmanov/jwtauth/internal/token"
)

const invalidCredentials = "invalid credentials"
const maxLoginBodyBytes = 4096
const refreshCookieName = "refresh_token"

type Handler struct {
	store        *UserStore
	refresh      *RefreshStore
	signer       *token.Signer
	cost         int
	dummyHash    string
	accessTTL    time.Duration
	refreshTTL   time.Duration
	cookieSecure bool
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	AccessToken string `json:"access_token"`
}

type meResponse struct {
	MeID string `json:"user_id"`
}

func NewHandler(store *UserStore, refresh *RefreshStore, signer *token.Signer,
	cost int, accessTTL, refreshTTL time.Duration, cookieSecure bool) (*Handler, error) {
	dummyHash, err := HashPassword("placeholder", cost)
	if err != nil {
		return nil, err
	}
	return &Handler{
		store:        store,
		refresh:      refresh,
		signer:       signer,
		cost:         cost,
		dummyHash:    dummyHash,
		accessTTL:    accessTTL,
		refreshTTL:   refreshTTL,
		cookieSecure: cookieSecure,
	}, nil
}

func (h *Handler) setRefreshCookie(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.refreshTTL.Seconds()),
	})
}

func (h *Handler) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func (h *Handler) mintAccessToken(userID string) (string, error) {
	now := time.Now()
	return h.signer.Sign(token.Claims{
		Subject:   userID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(h.accessTTL).Unix(),
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	user, ok := h.store.Get(req.Email)
	if !ok {
		_ = CheckPassword(h.dummyHash, req.Password)
		http.Error(w, invalidCredentials, http.StatusUnauthorized)
		return
	}
	if err := CheckPassword(user.PasswordHash, req.Password); err != nil {
		http.Error(w, invalidCredentials, http.StatusUnauthorized)
		return
	}

	familyID, err := newFamilyID()
	if err != nil {
		log.Printf("auth: new family id for %s: %v", user.ID, err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	refreshTok, err := h.refresh.Issue(user.ID, familyID, h.refreshTTL)
	if err != nil {
		log.Printf("auth: issue refresh token for %s: %v", user.ID, err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	accessTok, err := h.mintAccessToken(user.ID)
	if err != nil {
		log.Printf("auth: sign token for %s: %v", user.ID, err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.setRefreshCookie(w, refreshTok)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(loginResponse{AccessToken: accessTok}); err != nil {
		log.Printf("auth: encode login response for %s: %v", user.ID, err)
	}
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(refreshCookieName)
	if err != nil {
		http.Error(w, invalidCredentials, http.StatusUnauthorized)
		return
	}

	rec, err := h.refresh.Consume(c.Value)
	if err != nil {
		if errors.Is(err, ErrRefreshReused) {
			log.Printf("auth: refresh token reuse detected, family revoked")
		}
		h.clearRefreshCookie(w)
		http.Error(w, invalidCredentials, http.StatusUnauthorized)
		return
	}

	refreshTok, err := h.refresh.Issue(rec.UserID, rec.FamilyID, h.refreshTTL)
	if err != nil {
		log.Printf("auth: issue refresh token for %s: %v", rec.UserID, err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	accessTok, err := h.mintAccessToken(rec.UserID)
	if err != nil {
		log.Printf("auth: sign token for %s: %v", rec.UserID, err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.setRefreshCookie(w, refreshTok)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(loginResponse{AccessToken: accessTok}); err != nil {
		log.Printf("auth: encode refresh response for %s: %v", rec.UserID, err)
	}
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(refreshCookieName); err == nil {
		if rec, err := h.refresh.Consume(c.Value); err == nil {
			h.refresh.RevokeFamily(rec.FamilyID)
		}
	}

	h.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	sub, ok := SubjectFromContext(r.Context())
	if !ok {
		http.Error(w, unauthorized, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(meResponse{MeID: sub}); err != nil {
		log.Printf("auth: encode me response for %s: %v", sub, err)
	}
}
