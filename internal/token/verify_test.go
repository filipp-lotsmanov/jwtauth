package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const testNow int64 = 1760000000

func testSigner() *Signer {
	return &Signer{
		key:    []byte(vectorKey),
		issuer: vectorIssuer,
		now:    func() time.Time { return time.Unix(testNow, 0) },
	}
}

func TestParseRoundTrip(t *testing.T) {
	s := testSigner()

	in := Claims{
		Subject:   "user-42",
		Issuer:    vectorIssuer,
		IssuedAt:  testNow,
		ExpiresAt: testNow + 3600,
	}

	tok, err := s.Sign(in)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	out, err := s.Parse(tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if out != in {
		t.Errorf("claims:\n got  %+v\n want %+v", out, in)
	}
}

func forge(t *testing.T, s *Signer, h header, c Claims, signIt bool) string {
	t.Helper()

	hj, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cj, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	hs := base64.RawURLEncoding.EncodeToString(hj)
	cs := base64.RawURLEncoding.EncodeToString(cj)

	if !signIt {
		return hs + "." + cs + "."
	}
	return hs + "." + cs + "." + base64.RawURLEncoding.EncodeToString(s.sign(signingInput(hs, cs)))
}

func validClaims() Claims {
	return Claims{Subject: "user-42", Issuer: vectorIssuer, IssuedAt: testNow, ExpiresAt: testNow + 3600}
}

func mustSign(t *testing.T, s *Signer, c Claims) string {
	t.Helper()
	tok, err := s.Sign(c)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return tok
}

func TestParseRejects(t *testing.T) {
	s := testSigner()

	otherKey := &Signer{
		key:    []byte("a-completely-different-secret-key"),
		issuer: vectorIssuer,
		now:    func() time.Time { return time.Unix(testNow, 0) },
	}

	valid := mustSign(t, s, validClaims())
	parts := strings.Split(valid, ".")

	tamperedPayload := []byte(parts[1])
	if tamperedPayload[0] == 'e' {
		tamperedPayload[0] = 'f'
	} else {
		tamperedPayload[0] = 'e'
	}

	otherValid := mustSign(t, s, Claims{Subject: "user-99", IssuedAt: testNow, ExpiresAt: testNow + 3600})
	otherSig := strings.Split(otherValid, ".")[2]

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"empty", "", ErrMalformedToken},
		{"no dots", "notatoken", ErrMalformedToken},
		{"two segments", parts[0] + "." + parts[1], ErrMalformedToken},
		{"four segments", valid + ".extra", ErrMalformedToken},
		{"header not base64", "!!!." + parts[1] + "." + parts[2], ErrMalformedToken},
		{"header not json", base64.RawURLEncoding.EncodeToString([]byte("notjson")) + "." + parts[1] + "." + parts[2], ErrMalformedToken},
		{"alg none", forge(t, s, header{Alg: "none", Typ: "JWT"}, validClaims(), false), ErrUnexpectedAlg},
		{"alg hs512", forge(t, s, header{Alg: "HS512", Typ: "JWT"}, validClaims(), true), ErrUnexpectedAlg},
		{"tampered payload", parts[0] + "." + string(tamperedPayload) + "." + parts[2], ErrInvalidSignature},
		{"swapped signature", parts[0] + "." + parts[1] + "." + otherSig, ErrInvalidSignature},
		{"signed with other key", mustSign(t, otherKey, validClaims()), ErrInvalidSignature},
		{"signature not base64", parts[0] + "." + parts[1] + ".!!!", ErrMalformedToken},
		{"no exp", mustSign(t, s, Claims{Subject: "user-42"}), ErrExpired},
		{"expired past leeway", mustSign(t, s, Claims{Subject: "user-42", ExpiresAt: testNow - constLeeway - 1}), ErrExpired},
		{"nbf past leeway", mustSign(t, s, Claims{Subject: "user-42", ExpiresAt: testNow + 3600, NotBefore: testNow + constLeeway + 1}), ErrNotYetValid},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.Parse(tc.token)
			if !errors.Is(err, tc.want) {
				t.Errorf("error: got %v, want %v", err, tc.want)
			}
			if got != (Claims{}) {
				t.Errorf("claims: got %+v, want zero value", got)
			}
		})
	}
}

func TestParseRejectsForeignIssuer(t *testing.T) {
	minter := &Signer{
		key:    []byte(vectorKey),
		issuer: "some-other-service",
		now:    func() time.Time { return time.Unix(testNow, 0) },
	}

	tok := mustSign(t, minter, Claims{Subject: "user-42", ExpiresAt: testNow + 3600})

	got, err := testSigner().Parse(tok)
	if !errors.Is(err, ErrInvalidIssuer) {
		t.Errorf("error: got %v, want ErrInvalidIssuer", err)
	}
	if got != (Claims{}) {
		t.Errorf("claims: got %+v, want zero value", got)
	}
}

func TestLeewayBoundaries(t *testing.T) {
	s := testSigner()

	t.Run("exp exactly at leeway edge", func(t *testing.T) {
		tok := mustSign(t, s, Claims{Subject: "user-42", ExpiresAt: testNow - constLeeway})
		if _, err := s.Parse(tok); err != nil {
			t.Errorf("token at exp+leeway should be accepted, got %v", err)
		}
	})

	t.Run("nbf exactly at leeway edge", func(t *testing.T) {
		tok := mustSign(t, s, Claims{
			Subject:   "user-42",
			ExpiresAt: testNow + 3600,
			NotBefore: testNow + constLeeway,
		})
		if _, err := s.Parse(tok); err != nil {
			t.Errorf("token at nbf-leeway should be accepted, got %v", err)
		}
	})
}
