package internal

import (
	"os"
	"path/filepath"
	"strconv"
)

func GetListenPort() int {
	if port := os.Getenv("TUNWG_PORT"); port != "" {
		return Must(strconv.Atoi(port))
	}
	return 0
}

func Keystorage() string {
	store := os.Getenv("TUNWG_PATH")
	if store == "" {
		store = filepath.Join(Must(os.UserConfigDir()), "tunwg")
	}
	return store
}

func getKeyName() string {
	name := os.Getenv("TUNWG_KEY")
	if name == "" {
		name = filepath.Base(Must(os.Executable()))
	}
	return name
}

func ApiDomain() string {
	if domain := os.Getenv("TUNWG_API"); domain != "" {
		return domain
	}
	return "l.tunwg.com"
}

func AuthKey() string {
	return os.Getenv("TUNWG_AUTH")
}

// AuthSecret is the server-side HMAC secret for issued auth keys.
// When set, only issued keys are accepted; the shared AuthKey is ignored.
func AuthSecret() string {
	return os.Getenv("TUNWG_AUTH_SECRET")
}

// QuotaBytes is the daily traffic quota in bytes (rx+tx). The server applies
// it per auth credential, or per WireGuard peer when auth is disabled.
// 0 or unset disables quota enforcement.
func QuotaBytes() int64 {
	if v := os.Getenv("TUNWG_QUOTA_BYTES"); v != "" {
		return Must(strconv.ParseInt(v, 10, 64))
	}
	return 0
}

func ServerIp() string {
	ip := os.Getenv("TUNWG_IP")
	return ip
}

func SSLCertificateEmail() string {
	if email := os.Getenv("TUNWG_SSL_EMAIL"); email != "" {
		return email
	}
	return "certs@tunwg.com"
}

func UseRelay() bool {
	return os.Getenv("TUNWG_RELAY") != ""
}

func TestOnlyRunLocalhost() bool {
	return os.Getenv("TUNWG_TEST_LOCALHOST") == "true"
}
