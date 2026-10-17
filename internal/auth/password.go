package auth

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string, cost int) (string, error) {
	bytepassowrd := []byte(password)
	if len(bytepassowrd) > 72 {
		return "", errors.New("password too long")
	}
	hashed, err := bcrypt.GenerateFromPassword(bytepassowrd, cost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func CheckPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
