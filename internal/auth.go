package internal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// Auth keys issued by the server have the form "<id>.<sig>" where
// sig = hex(hmac-sha256(TUNWG_AUTH_SECRET, id))[:32]. Validation is
// stateless; individual ids can be revoked via the revocation file.

const authSigHexLen = 32

func signAuthKeyID(secret, id string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(id))
	return hex.EncodeToString(mac.Sum(nil))[:authSigHexLen]
}

// IssueAuthKey generates a new random key id and signs it.
func IssueAuthKey() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b[:])
	return id + "." + signAuthKeyID(AuthSecret(), id), nil
}

// ValidateAuthKey checks an "<id>.<sig>" key and returns its id.
// Always fails when TUNWG_AUTH_SECRET is not configured.
func ValidateAuthKey(key string) (id string, ok bool) {
	secret := AuthSecret()
	if secret == "" {
		return "", false
	}
	id, sig, found := strings.Cut(key, ".")
	if !found || id == "" {
		return "", false
	}
	want := signAuthKeyID(secret, id)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return "", false
	}
	return id, true
}
