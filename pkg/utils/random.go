package utils

import (
	"crypto/rand"
	"encoding/hex"
)

func GenerateRandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// GenerateAlphanumericToken produces an unbiased cryptographically random string
// containing uppercase letters, lowercase letters, and digits.
func GenerateAlphanumericToken(length int) string {
	if length <= 0 {
		return ""
	}
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	var randomByte [1]byte
	for i := 0; i < length; {
		if _, err := rand.Read(randomByte[:]); err != nil {
			panic(err)
		}
		// 62 * 4 = 248. Reject values >= 248 to eliminate modulo bias.
		if randomByte[0] < 248 {
			result[i] = chars[randomByte[0]%62]
			i++
		}
	}
	return string(result)
}
