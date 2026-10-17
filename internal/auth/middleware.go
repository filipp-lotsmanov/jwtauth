package auth

import (
	"context"
	"net/http"
	"strings"
)

const unauthorized = "unauthorized"

type contextKey struct{}

var subjectKey contextKey

func SubjectFromContext(ctx context.Context) (string, bool) {
	sub, ok := ctx.Value(subjectKey).(string)
	return sub, ok
}

func (h *Handler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		HeaderCheck := r.Header.Get("Authorization")
		if HeaderCheck == "" {
			http.Error(w, unauthorized, http.StatusUnauthorized)
			return
		}
		scheme, tok, found := strings.Cut(HeaderCheck, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") {
			http.Error(w, unauthorized, http.StatusUnauthorized)
			return
		}
		claims, err := h.signer.Parse(tok)
		if err != nil {
			http.Error(w, unauthorized, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), subjectKey, claims.Subject)
		next.ServeHTTP(w, r.WithContext(ctx))

	})
}
