package internal

import (
	"strings"
	"testing"
)

func TestAuthKeyRoundtrip(t *testing.T) {
	t.Setenv("TUNWG_AUTH_SECRET", "test-secret")

	key, err := IssueAuthKey()
	if err != nil {
		t.Fatalf("IssueAuthKey: %v", err)
	}
	id, ok := ValidateAuthKey(key)
	if !ok {
		t.Fatalf("issued key failed validation: %q", key)
	}
	if !strings.HasPrefix(key, id+".") {
		t.Errorf("id %q not a prefix of key %q", id, key)
	}
}

func TestAuthKeyRejections(t *testing.T) {
	t.Setenv("TUNWG_AUTH_SECRET", "test-secret")
	key, err := IssueAuthKey()
	if err != nil {
		t.Fatalf("IssueAuthKey: %v", err)
	}

	for _, bad := range []string{"", "hapi", "noseparator", key + "x", "otherid." + strings.Split(key, ".")[1]} {
		if _, ok := ValidateAuthKey(bad); ok {
			t.Errorf("key %q unexpectedly valid", bad)
		}
	}

	t.Setenv("TUNWG_AUTH_SECRET", "different-secret")
	if _, ok := ValidateAuthKey(key); ok {
		t.Error("key valid under a different secret")
	}

	t.Setenv("TUNWG_AUTH_SECRET", "")
	if _, ok := ValidateAuthKey(key); ok {
		t.Error("key valid with no secret configured")
	}
}
