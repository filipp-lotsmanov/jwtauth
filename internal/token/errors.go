package token

import "errors"

var (
	ErrWeakKey          = errors.New("token: key too short")
	ErrMalformedToken   = errors.New("token: malformed")
	ErrUnexpectedAlg    = errors.New("token: unexpected algorithm")
	ErrInvalidSignature = errors.New("token: invalid signature")
	ErrExpired          = errors.New("token: expired")
	ErrNotYetValid      = errors.New("token: not yet valid")
)
