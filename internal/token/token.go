package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Claims struct {
	Subject   string `json:"sub,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
}

type Signer struct {
	key    []byte
	issuer string
	now    func() time.Time
}

func NewSigner(key []byte, issuer string) (*Signer, error) {
	if len(key) < 32 {
		return nil, ErrWeakKey
	}
	if issuer == "" {
		return nil, ErrInvalidIssuer
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &Signer{key: k, issuer: issuer, now: time.Now}, nil
}

func (s *Signer) Sign(c Claims) (string, error) {
	c.Issuer = s.issuer
	MarshHeader, err := json.Marshal(header{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	headerSeg := base64.RawURLEncoding.EncodeToString(MarshHeader)

	MarshClaim, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	claimsSeg := base64.RawURLEncoding.EncodeToString(MarshClaim)

	input := signingInput(headerSeg, claimsSeg)

	sigSeg := base64.RawURLEncoding.EncodeToString(s.sign(input))

	return input + "." + sigSeg, nil
}

func (s *Signer) sign(signingInput string) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}

func signingInput(headerSeg, claimsSeg string) string {
	return headerSeg + "." + claimsSeg
}
