package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/inetaf/tcpproxy"
	"github.com/ntnj/tunwg/internal"
)

type sniRoute struct {
	host   string
	target string
}

type sniConfig struct {
	routes        []sniRoute
	proxyProtocol bool
}

func loadSNIConfig() (sniConfig, error) {
	return parseSNIConfig(os.Getenv("TUNWG_SNI_ROUTES"), os.Getenv("TUNWG_SNI_PROXY_PROTOCOL"), internal.ApiDomain())
}

func parseSNIConfig(rawRoutes, rawProxyProtocol, apiDomain string) (sniConfig, error) {
	var config sniConfig
	if value := strings.TrimSpace(rawProxyProtocol); value != "" {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return config, fmt.Errorf("TUNWG_SNI_PROXY_PROTOCOL must be a boolean: %w", err)
		}
		config.proxyProtocol = enabled
	}
	apiDomain = normalizeSNIHost(apiDomain)
	seen := make(map[string]bool)
	for index, line := range strings.Split(rawRoutes, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		host, target, ok := strings.Cut(line, "=")
		host = normalizeSNIHost(strings.TrimSpace(host))
		target = strings.TrimSpace(target)
		var problem string
		switch {
		case !ok:
			problem = "expected domain=host:port"
		case !validDNSName(host) || net.ParseIP(host) != nil:
			problem = "domain must be an exact DNS hostname"
		case host == apiDomain || strings.HasSuffix(host, "."+apiDomain):
			problem = "the API domain and its subdomains are reserved for tunwg"
		case seen[host]:
			problem = "duplicate domain"
		case !validSNITarget(target):
			problem = "target must be host:port with a port in 1..65535"
		}
		if problem != "" {
			return sniConfig{}, fmt.Errorf("TUNWG_SNI_ROUTES line %d: %s", index+1, problem)
		}
		seen[host] = true
		config.routes = append(config.routes, sniRoute{host: host, target: target})
	}
	return config, nil
}

func normalizeSNIHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func validDNSName(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validSNITarget(target string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return false
	}
	if _, err := netip.ParseAddr(host); err != nil && !validDNSName(normalizeSNIHost(host)) {
		return false
	}
	number, err := strconv.ParseUint(port, 10, 16)
	return err == nil && number > 0
}

// Build routes separately from listening so tests can use ephemeral ports and
// a tunnel target without initializing WireGuard or persistent access state.
func newSNIProxy(l80, l443 tcpproxy.Target, config sniConfig, tunnelTarget tcpproxy.SNITargetFunc) *tcpproxy.Proxy {
	proxy := &tcpproxy.Proxy{}
	proxy.AddRoute(":80", l80)
	apiDomain := normalizeSNIHost(internal.ApiDomain())
	proxy.AddSNIMatchRoute(":443", func(_ context.Context, host string) bool {
		return normalizeSNIHost(host) == apiDomain
	}, l443)

	staticTargets := make(map[string]tcpproxy.Target, len(config.routes))
	for _, route := range config.routes {
		version := 0
		if config.proxyProtocol {
			version = 1
		}
		staticTargets[route.host] = &tcpproxy.DialProxy{
			Addr:                 route.target,
			DialTimeout:          5 * time.Second,
			ProxyProtocolVersion: version,
			OnDialError: func(src net.Conn, err error) {
				slog.Warn("static SNI backend unavailable", "host", route.host, "target", route.target, "err", err)
				src.Close()
			},
		}
	}
	if len(staticTargets) > 0 {
		proxy.AddSNIRouteFunc(":443", func(_ context.Context, host string) (tcpproxy.Target, bool) {
			target, ok := staticTargets[normalizeSNIHost(host)]
			return target, ok
		})
	}
	proxy.AddSNIRouteFunc(":443", tunnelTarget)
	return proxy
}
