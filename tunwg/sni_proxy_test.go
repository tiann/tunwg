package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	proxyproto "github.com/armon/go-proxyproto"
	"github.com/inetaf/tcpproxy"
)

type sniEcho struct {
	Host       string
	RemoteAddr string
	URI        string
	Body       string
	Forwarded  string
}

func sniEchoHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	json.NewEncoder(w).Encode(sniEcho{r.Host, r.RemoteAddr, r.URL.RequestURI(), string(body), r.Header.Get("X-Forwarded-For")})
}

func newSNITLSBackend(t *testing.T, proxyProtocol bool) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(sniEchoHandler))
	if proxyProtocol {
		server.Listener = &proxyproto.Listener{Listener: server.Listener, ProxyHeaderTimeout: 3 * time.Second}
	}
	server.TLS = &tls.Config{NextProtos: []string{"http/1.1", "acme-tls/1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func startSNITestProxy(t *testing.T, config sniConfig, api tcpproxy.Target, tunnel tcpproxy.SNITargetFunc) (httpsAddr, httpAddr string) {
	t.Helper()
	l80 := &tcpproxy.TargetListener{Address: "http-test"}
	httpServer := &http.Server{Handler: sslRedirect(), ReadHeaderTimeout: time.Second}
	go httpServer.Serve(l80)
	t.Cleanup(func() { httpServer.Close() })
	listeners := make(map[string]net.Listener)
	for _, address := range []string{":80", ":443"} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		listeners[address] = listener
	}
	proxy := newSNIProxy(l80, api, config, tunnel)
	proxy.ListenFunc = func(_, address string) (net.Listener, error) {
		return listeners[address], nil
	}
	if err := proxy.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		proxy.Close()
		proxy.Wait()
	})
	return listeners[":443"].Addr().String(), listeners[":80"].Addr().String()
}

func connectSNI(address, host string, protocols []string) (*tls.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{
		ServerName: host,
		// Test backends use httptest's certificate; tests also compare the
		// received certificate with the backend's to verify TLS passthrough.
		InsecureSkipVerify: true,
		NextProtos:         protocols,
	})
}

func requestSNIEcho(t *testing.T, conn *tls.Conn, host string) sniEcho {
	t.Helper()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	req, err := http.NewRequest(http.MethodPost, "https://"+host+"/v1/push?source=test", strings.NewReader("encrypted-envelope"))
	if err != nil {
		t.Fatal(err)
	}
	req.Close = true
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result sniEcho
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestSNIProxyStaticTLS(t *testing.T) {
	t.Setenv("TUNWG_API", "relay.example.com")
	for _, useProxy := range []bool{false, true} {
		t.Run(fmt.Sprintf("proxy_protocol=%v", useProxy), func(t *testing.T) {
			backend := newSNITLSBackend(t, useProxy)
			config, err := parseSNIConfig("push.example.com="+backend.Listener.Addr().String(), fmt.Sprint(useProxy), "relay.example.com")
			if err != nil {
				t.Fatal(err)
			}
			var tunnelCalls atomic.Int32
			address, _ := startSNITestProxy(t, config, &tcpproxy.TargetListener{}, func(context.Context, string) (tcpproxy.Target, bool) {
				tunnelCalls.Add(1)
				return nil, false
			})
			conn, err := connectSNI(address, "PUSH.EXAMPLE.COM", []string{"http/1.1"})
			if err != nil {
				t.Fatal(err)
			}
			source := conn.LocalAddr().String()
			if !bytes.Equal(conn.ConnectionState().PeerCertificates[0].Raw, backend.Certificate().Raw) {
				t.Fatal("the client did not receive the backend's TLS certificate")
			}
			echo := requestSNIEcho(t, conn, "push.example.com")
			if echo.URI != "/v1/push?source=test" || echo.Body != "encrypted-envelope" || echo.Host != "push.example.com" {
				t.Fatalf("request changed: %+v", echo)
			}
			if useProxy && echo.RemoteAddr != source {
				t.Fatalf("PROXY source = %q, want %q", echo.RemoteAddr, source)
			}
			conn, err = connectSNI(address, "push.example.com", []string{"acme-tls/1"})
			if err != nil {
				t.Fatal(err)
			}
			if conn.ConnectionState().NegotiatedProtocol != "acme-tls/1" {
				t.Fatal("ACME ALPN did not reach the backend")
			}
			conn.Close()
			if tunnelCalls.Load() != 0 {
				t.Fatal("static traffic reached the WireGuard resolver")
			}
		})
	}
}

func TestSNIProxyRoutingAndBackendFailure(t *testing.T) {
	t.Setenv("TUNWG_API", "relay.example.com")
	apiListener := &tcpproxy.TargetListener{Address: "api-test"}
	api := httptest.NewUnstartedServer(http.HandlerFunc(sniEchoHandler))
	api.Listener.Close()
	api.Listener = apiListener
	api.StartTLS()
	t.Cleanup(api.Close)
	tunnelBackend := newSNITLSBackend(t, false)
	staticBackend := newSNITLSBackend(t, true)
	unavailable, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	missingAddress := unavailable.Addr().String()
	unavailable.Close()
	config, err := parseSNIConfig("down.example.com="+missingAddress+"\npush.example.com="+staticBackend.Listener.Addr().String(), "true", "relay.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var tunnelCalls atomic.Int32
	address, httpAddress := startSNITestProxy(t, config, apiListener, func(_ context.Context, host string) (tcpproxy.Target, bool) {
		tunnelCalls.Add(1)
		if host == "encoded.relay.example.com" || host == "custom.example.com" {
			return tcpproxy.To(tunnelBackend.Listener.Addr().String()), true
		}
		return nil, false
	})
	if conn, err := connectSNI(address, "down.example.com", nil); err == nil {
		conn.Close()
		t.Fatal("unavailable backend unexpectedly accepted TLS")
	}
	if tunnelCalls.Load() != 0 {
		t.Fatal("failed static route fell through to the tunnel resolver")
	}
	for _, host := range []string{"relay.example.com", "push.example.com", "encoded.relay.example.com", "custom.example.com"} {
		conn, err := connectSNI(address, host, []string{"http/1.1"})
		if err != nil {
			t.Fatalf("%s after backend failure: %v", host, err)
		}
		source := conn.LocalAddr().String()
		echo := requestSNIEcho(t, conn, host)
		if host == "relay.example.com" && echo.RemoteAddr != source {
			t.Fatalf("API source IP/port changed: got %s, want %s", echo.RemoteAddr, source)
		}
	}
	if tunnelCalls.Load() != 2 {
		t.Fatalf("tunnel resolver calls = %d, want 2", tunnelCalls.Load())
	}
	for _, host := range []string{"unknown.example.com", ""} {
		if conn, err := connectSNI(address, host, nil); err == nil {
			conn.Close()
			t.Fatalf("unknown/missing SNI %q unexpectedly accepted", host)
		}
	}
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, _ := http.NewRequest(http.MethodGet, "http://"+httpAddress+"/hello?x=1", nil)
	request.Host = "push.example.com"
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusMovedPermanently || response.Header.Get("Location") != "https://push.example.com/hello?x=1" {
		t.Fatalf("HTTP redirect changed: %s, %s", response.Status, response.Header.Get("Location"))
	}
}
