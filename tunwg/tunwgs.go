package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/inetaf/tcpproxy"
	"github.com/ntnj/tunwg/internal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func tunwgServer() {
	flag.Parse()
	configureLogging()
	if internal.GetListenPort() <= 0 {
		fatal("TUNWG_PORT needs to be set")
	} else if internal.ServerIp() == "" {
		fatal("TUNWG_IP needs to be set")
	}
	if err := internal.Initialize(); err != nil {
		fatal("failed to initialize", "err", err)
	}
	if err := globalAccess.load(); err != nil {
		fatal("access state unavailable", "err", err)
	}
	if err := globalAccess.restorePeers(); err != nil {
		fatal("failed to restore peers safely", "err", err)
	}
	if err := globalAccess.reconcile(); err != nil {
		fatal("failed to reconcile access state", "err", err)
	}
	l443 := &tcpproxy.TargetListener{Address: "https"}
	go func() {
		srv := &http.Server{
			Handler:           apiMux(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		if err := srv.Serve(tls.NewListener(l443, internal.GetTLSConfig())); err != nil {
			fatal("failed to serve api", "err", err)
		}
	}()
	l80 := &tcpproxy.TargetListener{Address: "http"}
	go func() {
		srv := &http.Server{
			Handler:           sslRedirect(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		if err := srv.Serve(l80); err != nil {
			fatal("failed to serve redirect handler", "err", err)
		}
	}()
	go internal.BackgroundLogger(10 * time.Second)
	go globalAccess.run(30 * time.Second)
	fatal("failed to run", "err", runSniProxy(l80, l443))
}

func allowUserKey(key wgtypes.Key, endpoint string) error {
	ipc := []string{
		"public_key=" + hex.EncodeToString(key[:]),
		fmt.Sprintf("allowed_ip=%s/128", internal.GetIPForKey(key)),
	}
	if endpoint != "" {
		ipc = append(ipc, "endpoint="+endpoint)
	}
	return internal.WgSetIpc(ipc)
}

func sslRedirect() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/.well-known/acme-challenge/", &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			ipport, err := getIPForDomain(pr.In.Host)
			if err != nil {
				slog.Warn("unable to find host", "host", pr.In.Host, "err", err)
				return
			}
			newPort := netip.AddrPortFrom(ipport.Addr(), 80)
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = fmt.Sprintf("%v", newPort.String())
		},
		Transport: &http.Transport{
			DialContext: internal.DialWg,
		},
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
	})
	return mux
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func apiMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/issue", func(w http.ResponseWriter, r *http.Request) {
		if internal.AuthSecret() == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ip := clientIP(r)
		key, err := globalAccess.issueAuthKey(ip, defaultIssueLimitPerIPPerDay, 24*time.Hour)
		if err != nil {
			switch {
			case errors.Is(err, errIssueRateLimited):
				var rateLimitErr *issueRateLimitError
				if errors.As(err, &rateLimitErr) {
					seconds := (rateLimitErr.retryAfter + time.Second - 1) / time.Second
					w.Header().Set("Retry-After", strconv.FormatInt(int64(seconds), 10))
				}
				w.WriteHeader(http.StatusTooManyRequests)
			case errors.Is(err, errAccessStateUnavailable):
				w.WriteHeader(http.StatusServiceUnavailable)
			default:
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}
		slog.Info("issued auth key", "ip", ip, "key_id", strings.SplitN(key, ".", 2)[0])
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]string{"key": key})
	})
	mux.HandleFunc("/add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		reqBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		req := internal.AddPeerReq{}
		if err := json.Unmarshal(reqBytes, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		clientKey, err := wgtypes.NewKey(req.Key)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		credential, err := globalAccess.registerPeer(clientKey, r.Header.Get("X-Authorization"))
		if err != nil {
			slog.Warn("rejected peer add", "ip", clientIP(r), "key_id", credential.keyID, "peer", clientKey.String(), "err", err)
			switch {
			case errors.Is(err, errAccessUnauthorized):
				w.WriteHeader(http.StatusForbidden)
			case errors.Is(err, errRevocationsUnavailable), errors.Is(err, errAccessStateUnavailable):
				w.WriteHeader(http.StatusServiceUnavailable)
			case errors.Is(err, errPeerBlocked), errors.Is(err, errPeerLimitReached):
				w.WriteHeader(http.StatusTooManyRequests)
			default:
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}
		slog.Info("peer added", "ip", clientIP(r), "key_id", credential.keyID, "peer", clientKey.String())
		key := internal.GetPublicKey()
		resp := internal.AddPeerResp{
			Key:      key[:],
			Endpoint: net.JoinHostPort(internal.ServerIp(), strconv.Itoa(internal.GetListenPort())),
		}
		respBytes, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)
	})
	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		if proto := r.Header.Get("Upgrade"); proto != "udp-relay" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		h, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", "udp-relay")
		w.WriteHeader(http.StatusSwitchingProtocols)
		conn, _, err := h.Hijack()
		if err != nil {
			slog.Error("hijack error", "err", err)
			return
		}
		defer conn.Close()
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			slog.Error("relay listen error", "err", err)
			return
		}
		if err := internal.RelayServer(conn, udpConn, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: internal.GetListenPort()}); err != nil && !errors.Is(err, io.EOF) {
			slog.Error("relay error", "err", err)
		}
	})
	return mux
}

func runSniProxy(l80, l443 *tcpproxy.TargetListener) error {
	var proxy tcpproxy.Proxy
	proxy.AddRoute(":80", l80)
	proxy.AddSNIRoute(":443", internal.ApiDomain(), l443)
	proxy.AddSNIRouteFunc(":443", func(ctx context.Context, sniName string) (tcpproxy.Target, bool) {
		slog.Debug("received request", "server_name", sniName)
		addr, err := getIPForDomain(sniName)
		if err != nil {
			slog.Debug("dispatch error", "server_name", sniName, "err", err)
			return nil, false
		}
		return &tcpproxy.DialProxy{
			Addr:                 addr.String(),
			DialContext:          internal.DialWg,
			DialTimeout:          5 * time.Second,
			ProxyProtocolVersion: 1,
		}, true
	})
	return proxy.Run()
}

func getIPForDomain(sniName string) (*netip.AddrPort, error) {
	sniName = strings.ToLower(strings.TrimSuffix(sniName, "."))
	encodedIP, ok := internal.ExtractEncodedLabel(sniName, internal.ApiDomain())
	if !ok {
		if strings.HasSuffix(sniName, "."+strings.ToLower(internal.ApiDomain())) {
			return nil, fmt.Errorf("rejecting invalid hostname: %v", sniName)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cname, err := net.DefaultResolver.LookupCNAME(ctx, sniName)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup cname %v: %v", sniName, err)
		}
		slog.Debug("resolved cname", "server_name", sniName, "cname", cname)
		encodedIP, ok = internal.ExtractEncodedLabel(cname, internal.ApiDomain())
		if !ok {
			return nil, fmt.Errorf("no proper suffix: %v", sniName)
		}
	}
	addr := internal.LookupEncodedIPPort(encodedIP)
	if addr == nil {
		return nil, fmt.Errorf("error in dispatching: %v", sniName)
	}
	return addr, nil
}
