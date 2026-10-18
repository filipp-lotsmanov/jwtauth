package main

import (
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/filipp-lotsmanov/jwtauth/internal/auth"
	"github.com/filipp-lotsmanov/jwtauth/internal/token"
)

const seedUserID = "u1"

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing required env var: %s", key)
	}
	return v
}

func main() {
	key, err := base64.RawURLEncoding.DecodeString(mustEnv("JWT_SECRET"))
	if err != nil {
		log.Fatalf("decode JWT_SECRET: %v", err)
	}

	issuer := mustEnv("JWT_ISSUER")
	port := mustEnv("PORT")
	seedEmail := mustEnv("SEED_USER_EMAIL")
	seedPassword := mustEnv("SEED_USER_PASSWORD")

	accessTTL, err := time.ParseDuration(mustEnv("ACCESS_TOKEN_TTL"))
	if err != nil {
		log.Fatalf("parse ACCESS_TOKEN_TTL: %v", err)
	}

	refreshTTL, err := time.ParseDuration(mustEnv("REFRESH_TOKEN_TTL"))
	if err != nil {
		log.Fatalf("parse REFRESH_TOKEN_TTL: %v", err)
	}

	cost, err := strconv.Atoi(mustEnv("BCRYPT_COST"))
	if err != nil {
		log.Fatalf("parse BCRYPT_COST: %v", err)
	}
	cookieSecure, err := strconv.ParseBool(mustEnv("COOKIE_SECURE"))
	if err != nil {
		log.Fatalf("parse COOKIE_SECURE: %v", err)
	}

	signer, err := token.NewSigner(key, issuer)
	if err != nil {
		log.Fatalf("create signer: %v", err)
	}

	store := auth.NewUserStore()
	refreshStore := auth.NewRefreshStore()

	seedHash, err := auth.HashPassword(seedPassword, cost)
	if err != nil {
		log.Fatalf("hash seed password: %v", err)
	}
	if err := store.Add(auth.User{
		ID:           seedUserID,
		Email:        seedEmail,
		PasswordHash: seedHash,
	}); err != nil {
		log.Fatalf("seed user: %v", err)
	}

	h, err := auth.NewHandler(store, refreshStore, signer, cost, accessTTL, refreshTTL, cookieSecure)
	if err != nil {
		log.Fatalf("create handler: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", h.Login)
	mux.HandleFunc("POST /refresh", h.Refresh)
	mux.HandleFunc("POST /logout", h.Logout)
	mux.Handle("GET /me", h.RequireAuth(http.HandlerFunc(h.Me)))
	mux.Handle("/", http.FileServerFS(os.DirFS("web/dist")))

	log.Printf("listening on :%s (issuer %q, access TTL %s, refresh TTL %s)",
		port, issuer, accessTTL, refreshTTL)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
