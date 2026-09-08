package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseSNIConfig(t *testing.T) {
	tests := []struct {
		name   string
		routes string
		proxy  string
		want   sniConfig
	}{
		{name: "disabled"},
		{name: "blank lines", routes: " \n\r\n\t", proxy: "false"},
		{
			name:   "single route without PROXY",
			routes: "push.example.com=127.0.0.1:8443",
			want:   sniConfig{routes: []sniRoute{{"push.example.com", "127.0.0.1:8443"}}},
		},
		{
			name:   "multiple normalized domains and backend address forms",
			routes: "\n Push.Example.COM. = 127.0.0.1:8443 \r\n\nstatus.example.com=[::1]:9443\napp.example.com=caddy:443\n",
			proxy:  " true ",
			want: sniConfig{proxyProtocol: true, routes: []sniRoute{
				{"push.example.com", "127.0.0.1:8443"},
				{"status.example.com", "[::1]:9443"},
				{"app.example.com", "caddy:443"},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSNIConfig(tt.routes, tt.proxy, "relay.example.com")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("config = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseSNIConfigRejectsInvalidRoutes(t *testing.T) {
	for _, route := range []string{
		"push.example.com",
		"=localhost:443",
		"push.example.com=",
		"push.example.com=localhost",
		"push.example.com=:443",
		"push.example.com=localhost:0",
		"push.example.com=localhost:65536",
		"push.example.com=localhost:https",
		"push.example.com=localhost:-1",
		"push.example.com=https://localhost:443",
		"push.example.com=localhost:443/path",
		"push.example.com=::1:443",
		"push.example.com=bad_host:443",
		"*.example.com=localhost:443",
		"https://push.example.com=localhost:443",
		"push.example.com:443=localhost:443",
		"push..example.com=localhost:443",
		"-push.example.com=localhost:443",
		"push-.example.com=localhost:443",
		strings.Repeat("a", 64) + ".example.com=localhost:443",
		"127.0.0.1=localhost:443",
		"RELAY.EXAMPLE.COM.=localhost:443",
		"push.relay.example.com=localhost:443",
		"push.example.com=localhost:443\nPUSH.EXAMPLE.COM.=localhost:9443",
	} {
		t.Run(route, func(t *testing.T) {
			_, err := parseSNIConfig(route, "", "relay.example.com")
			if err == nil || !strings.Contains(err.Error(), "TUNWG_SNI_ROUTES line ") {
				t.Fatalf("expected a configuration error with a line number, got %v", err)
			}
		})
	}
	if _, err := parseSNIConfig("", "maybe", "relay.example.com"); err == nil || !strings.Contains(err.Error(), "TUNWG_SNI_PROXY_PROTOCOL") {
		t.Fatalf("invalid PROXY setting: %v", err)
	}
}

func TestLoadSNIConfig(t *testing.T) {
	t.Setenv("TUNWG_API", "relay.example.com")
	t.Setenv("TUNWG_SNI_ROUTES", "push.example.com=localhost:8443")
	t.Setenv("TUNWG_SNI_PROXY_PROTOCOL", "true")
	config, err := loadSNIConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(config.routes) != 1 || !config.proxyProtocol {
		t.Fatalf("config = %+v", config)
	}
	t.Setenv("TUNWG_SNI_ROUTES", "relay.example.com=localhost:8443")
	if _, err := loadSNIConfig(); err == nil {
		t.Fatal("API domain from the environment must be reserved")
	}
}
