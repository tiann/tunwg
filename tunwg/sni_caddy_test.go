package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/inetaf/tcpproxy"
)

// Opt-in because the regular Go suite must not require a Docker daemon or
// download images. Automatic certificates are disabled and replaced with a
// local certificate; the deployment's PROXY/TLS/header handling is unchanged.
func TestSNIProxyCaddy(t *testing.T) {
	if os.Getenv("TUNWG_TEST_CADDY") != "1" {
		t.Skip("set TUNWG_TEST_CADDY=1 to run the Docker integration test")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the deployment uses Linux host networking")
	}
	t.Setenv("TUNWG_API", "relay.example.com")
	dir := t.TempDir()
	certificateServer := newSNITLSBackend(t, false)
	certificate := certificateServer.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{
		"test.crt": {Type: "CERTIFICATE", Bytes: certificate.Certificate[0]},
		"test.key": {Type: "PRIVATE KEY", Bytes: key},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	backend := httptest.NewServer(http.HandlerFunc(sniEchoHandler))
	t.Cleanup(backend.Close)
	portListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	caddyAddress := portListener.Addr().String()
	_, port, _ := net.SplitHostPort(caddyAddress)
	portListener.Close()

	template, err := os.ReadFile("../examples/push-relay/Caddyfile")
	if err != nil {
		t.Fatal(err)
	}
	configText := strings.ReplaceAll(string(template), "8443", port)
	configText = strings.ReplaceAll(configText, "auto_https disable_redirects", "auto_https off")
	configText = strings.ReplaceAll(configText, "127.0.0.1:8790", backend.Listener.Addr().String())
	tlsStart := strings.Index(configText, "\ttls {")
	tlsEnd := strings.Index(configText, "\n\treverse_proxy ")
	if tlsStart < 0 || tlsEnd < tlsStart {
		t.Fatal("could not locate the deployment's ACME issuer block")
	}
	configText = configText[:tlsStart] + "\ttls /fixtures/test.crt /fixtures/test.key\n" + configText[tlsEnd:]
	if err := os.WriteFile(filepath.Join(dir, "Caddyfile"), []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}

	container := fmt.Sprintf("tunwg-sni-test-%d", time.Now().UnixNano())
	cmd := exec.Command("docker", "run", "--rm", "--name", container, "--network", "host",
		"--mount", "type=bind,src="+dir+",dst=/fixtures,readonly",
		"--env", "PUSH_DOMAIN=push.example.com", "caddy:2.11.4",
		"caddy", "run", "--config", "/fixtures/Caddyfile", "--adapter", "caddyfile")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		exec.CommandContext(ctx, "docker", "rm", "--force", container).Run()
		select {
		case <-done:
		case <-ctx.Done():
			cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			t.Log(output.String())
		}
	})
	deadline := time.Now().Add(45 * time.Second)
	for {
		if conn, err := net.DialTimeout("tcp", caddyAddress, 100*time.Millisecond); err == nil {
			conn.Close()
			break
		}
		select {
		case <-done:
			t.Fatalf("Caddy exited before listening: %v", waitErr)
		case <-time.After(50 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("timed out waiting for Caddy")
			}
		}
	}

	config, err := parseSNIConfig("push.example.com="+caddyAddress, "true", "relay.example.com")
	if err != nil {
		t.Fatal(err)
	}
	api := &tcpproxy.TargetListener{}
	api.Close()
	address, _ := startSNITestProxy(t, config, api, func(context.Context, string) (tcpproxy.Target, bool) { return nil, false })
	for _, source := range []string{"127.0.0.2", "127.0.0.3"} {
		conn, err := tls.DialWithDialer(&net.Dialer{
			Timeout:   3 * time.Second,
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)},
		}, "tcp", address, &tls.Config{
			ServerName:         "push.example.com",
			InsecureSkipVerify: true, // local httptest certificate
		})
		if err != nil {
			t.Fatal(err)
		}
		echo := requestSNIEcho(t, conn, "push.example.com")
		if echo.Forwarded != source {
			t.Fatalf("forwarded IP = %q, want %q; spoofed header was %q", echo.Forwarded, source, "203.0.113.99")
		}
		if echo.Body != "encrypted-envelope" || echo.URI != "/v1/push?source=test" {
			t.Fatalf("request changed: %+v", echo)
		}
	}
}
