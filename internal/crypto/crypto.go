// Package crypto holds server-side primitives that never see a secret payload.
// AES is intentionally absent. Ciphertext is opaque to every caller.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"

	"golang.org/x/crypto/argon2"
)

// NewID returns 16 bytes from crypto/rand, encoded as unpadded base64url.
func NewID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Random returns n bytes from crypto/rand.
func Random(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// HashToken is SHA-256 over the raw token bytes.
func HashToken(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}

// Argon2id derives a 32-byte hash. Parameters must already be at or above the floor.
func Argon2id(password, salt []byte, time, memoryKiB uint32, threads uint8) []byte {
	return argon2.IDKey(password, salt, time, memoryKiB, threads, 32)
}

// Equal compares two equal-length slices in constant time.
func Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Wipe zeroes a buffer that held a password or token.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
