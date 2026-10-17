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

type Handler struct {
	store      *UserStore
	refresh    *RefreshStore
	signer     *token.Signer
	cost       int
	dummyHash  string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type meResponse struct {
	MeID string `json:"user_id"`
}

func (h *Handler) mintAccessToken(userID string) (string, error) {
	now := time.Now()
	return h.signer.Sign(token.Claims{
		Subject:   userID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(h.accessTTL).Unix(),
	})
}

func NewHandler(store *UserStore, refresh *RefreshStore, signer *token.Signer,
	cost int, accessTTL, refreshTTL time.Duration) (*Handler, error) {
	dummyHash, err := HashPassword("placeholder", cost)
	if err != nil {
		return nil, err
	}
	return &Handler{
		store:      store,
		refresh:    refresh,
		signer:     signer,
		cost:       cost,
		dummyHash:  dummyHash,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}, nil
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)

	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	rec, err := h.refresh.Consume(req.RefreshToken)
	if err != nil {
		if errors.Is(err, ErrRefreshReused) {
			log.Printf("auth: refresh token reuse detected, family revoked")
		}
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

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(loginResponse{
		AccessToken:  accessTok,
		RefreshToken: refreshTok,
	}); err != nil {
		log.Printf("auth: encode refresh response for %s: %v", rec.UserID, err)
	}
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)

	var request refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	record, err := h.refresh.Consume(request.RefreshToken)
	if err == nil {
		h.refresh.RevokeFamily(record.FamilyID)
	}

	w.WriteHeader(http.StatusNoContent)
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

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(loginResponse{
		AccessToken:  accessTok,
		RefreshToken: refreshTok,
	}); err != nil {
		log.Printf("auth: encode login response for %s: %v", user.ID, err)
	}
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
