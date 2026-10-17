package auth

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

const testCost = bcrypt.MinCost

func TestHashAndCheckRoundTrip(t *testing.T) {
	const password = "correct-horse-battery-staple"

	hash, err := HashPassword(password, testCost)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if err := CheckPassword(hash, password); err != nil {
		t.Errorf("CheckPassword rejected the correct password: %v", err)
	}
}

func TestCheckPasswordRejectsWrong(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery-staple", testCost)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if err := CheckPassword(hash, "wrong-password"); err == nil {
		t.Error("CheckPassword accepted a wrong password")
	}
}

func TestHashPasswordRejectsTooLong(t *testing.T) {
	_, err := HashPassword(strings.Repeat("a", 73), testCost)
	if err == nil {
		t.Error("HashPassword accepted a 73-byte password")
	}
}

func TestHashPasswordAcceptsExactly72(t *testing.T) {
	if _, err := HashPassword(strings.Repeat("a", 72), testCost); err != nil {
		t.Errorf("HashPassword rejected a 72-byte password: %v", err)
	}
}

func TestHashPasswordSaltsEachCall(t *testing.T) {
	const password = "correct-horse-battery-staple"

	first, err := HashPassword(password, testCost)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	second, err := HashPassword(password, testCost)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if first == second {
		t.Error("two hashes of the same password are identical; salt is not random")
	}
	if err := CheckPassword(first, password); err != nil {
		t.Errorf("first hash does not verify: %v", err)
	}
	if err := CheckPassword(second, password); err != nil {
		t.Errorf("second hash does not verify: %v", err)
	}
}

func TestCheckPasswordRejectsGarbageHash(t *testing.T) {
	if err := CheckPassword("not-a-bcrypt-hash", "anything"); err == nil {
		t.Error("CheckPassword accepted a malformed hash")
	}
}

func TestHashPasswordRejectsBadCost(t *testing.T) {
	if _, err := HashPassword("whatever", 99); err == nil {
		t.Error("HashPassword accepted cost 99")
	}
}
