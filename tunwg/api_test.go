package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAccessEndpointsRequirePost(t *testing.T) {
	t.Setenv("TUNWG_AUTH_SECRET", "secret")
	for _, path := range []string{"/issue", "/add"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			response := httptest.NewRecorder()
			apiMux().ServeHTTP(response, request)
			if response.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d", response.Code)
			}
		})
	}
}

func TestAddRequestBodyIsBounded(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/add", strings.NewReader(strings.Repeat("x", (4<<10)+1)))
	response := httptest.NewRecorder()
	apiMux().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestIssueLimitAndRetryAfter(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	config := &testAccessConfig{now: now, secret: "secret"}
	controller := newTestController(
		&memoryAccessStore{},
		newFakePeerDevice(),
		&fakeRevocationSource{},
		config,
	)
	if err := controller.load(); err != nil {
		t.Fatal(err)
	}
	previous := globalAccess
	globalAccess = controller
	t.Cleanup(func() { globalAccess = previous })
	t.Setenv("TUNWG_AUTH_SECRET", "secret")

	for i := 0; i < defaultIssueLimitPerIPPerDay; i++ {
		request := httptest.NewRequest(http.MethodPost, "/issue", nil)
		request.RemoteAddr = "192.0.2.1:1234"
		response := httptest.NewRecorder()
		apiMux().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("issue %d status = %d", i, response.Code)
		}
	}
	config.now = now.Add(23 * time.Hour)
	request := httptest.NewRequest(http.MethodPost, "/issue", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	response := httptest.NewRecorder()
	apiMux().ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("limited status = %d", response.Code)
	}
	if got := response.Header().Get("Retry-After"); got != "3600" {
		t.Fatalf("Retry-After = %q, want 3600", got)
	}
}
