package token

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const constLeeway int64 = 60

func (s *Signer) Parse(tokenStr string) (Claims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("%w: expected 3 segments, got %d", ErrMalformedToken, len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: decode header: %v", ErrMalformedToken, err)
	}

	var h header
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return Claims{}, fmt.Errorf("%w: unmarshal header: %v", ErrMalformedToken, err)
	}

	if h.Alg != "HS256" {
		return Claims{}, fmt.Errorf("%w: %q", ErrUnexpectedAlg, h.Alg)
	}

	expected := s.sign(signingInput(parts[0], parts[1]))

	provided, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: decode signature: %v", ErrMalformedToken, err)
	}

	if !hmac.Equal(expected, provided) {
		return Claims{}, ErrInvalidSignature
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: decode claims: %v", ErrMalformedToken, err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return Claims{}, fmt.Errorf("%w: unmarshal claims: %v", ErrMalformedToken, err)
	}

	if err := s.Validate(claims); err != nil {
		return Claims{}, err
	}

	return claims, nil
}

func (s *Signer) Validate(claims Claims) error {
	now := s.now().Unix()

	if claims.ExpiresAt == 0 {
		return fmt.Errorf("%w: no exp claim", ErrExpired)
	}
	if now > claims.ExpiresAt+constLeeway {
		return fmt.Errorf("%w: exp %d, now %d", ErrExpired, claims.ExpiresAt, now)
	}
	if claims.NotBefore != 0 && now < claims.NotBefore-constLeeway {
		return fmt.Errorf("%w: nbf %d, now %d", ErrNotYetValid, claims.NotBefore, now)
	}

	return nil
}
