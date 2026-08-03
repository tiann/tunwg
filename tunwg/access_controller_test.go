package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newPeerKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicKey()
}

func cloneDiskState(state accessDiskState) accessDiskState {
	data, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	copy := accessDiskState{}
	if err := json.Unmarshal(data, &copy); err != nil {
		panic(err)
	}
	return copy
}

type memoryAccessStore struct {
	mu      sync.Mutex
	state   accessDiskState
	found   bool
	saveErr error
	saves   int
}

func (s *memoryAccessStore) Load() (accessDiskState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneDiskState(s.state), s.found, nil
}

func (s *memoryAccessStore) Save(state accessDiskState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves++
	if s.saveErr != nil {
		return s.saveErr
	}
	s.state = cloneDiskState(state)
	s.found = true
	return nil
}

type fakePeerDevice struct {
	mu          sync.Mutex
	peers       map[wgtypes.Key]wgtypes.Peer
	addErr      error
	removeErr   error
	snapshotErr error
	addCalls    int
	removeCalls int
}

func newFakePeerDevice() *fakePeerDevice {
	return &fakePeerDevice{peers: make(map[wgtypes.Key]wgtypes.Peer)}
}

func (d *fakePeerDevice) AddPeer(key wgtypes.Key, endpoint string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.addCalls++
	if d.addErr != nil {
		return d.addErr
	}
	peer := d.peers[key]
	peer.PublicKey = key
	if endpoint != "" {
		resolved, err := net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			return err
		}
		peer.Endpoint = resolved
	}
	d.peers[key] = peer
	return nil
}

func (d *fakePeerDevice) RemovePeer(key wgtypes.Key) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.removeCalls++
	if d.removeErr != nil {
		return d.removeErr
	}
	delete(d.peers, key)
	return nil
}

func (d *fakePeerDevice) Snapshot() (*wgtypes.Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.snapshotErr != nil {
		return nil, d.snapshotErr
	}
	device := &wgtypes.Device{}
	for _, peer := range d.peers {
		device.Peers = append(device.Peers, peer)
	}
	return device, nil
}

func (d *fakePeerDevice) setPeer(peer wgtypes.Peer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.peers[peer.PublicKey] = peer
}

type fakeRevocationSource struct {
	mu      sync.Mutex
	revoked map[string]bool
	err     error
}

func (s *fakeRevocationSource) Load() (map[string]bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	copy := make(map[string]bool, len(s.revoked))
	for id, revoked := range s.revoked {
		copy[id] = revoked
	}
	return copy, nil
}

type testAccessConfig struct {
	now       time.Time
	secret    string
	legacyKey string
	quota     int64
}

func newTestController(store accessStateStore, device peerDevice, revocations revocationSource, config *testAccessConfig) *accessController {
	controller := newAccessController(store, device, revocations)
	controller.now = func() time.Time { return config.now }
	controller.authSecret = func() string { return config.secret }
	controller.legacyKey = func() string { return config.legacyKey }
	controller.validateKey = func(key string) (string, bool) {
		if key == "token:"+config.secret && config.secret != "" {
			return "issued-id", true
		}
		return "", false
	}
	controller.issueKey = func() (string, error) { return "issued-id.signature", nil }
	controller.quotaBytes = func() int64 { return config.quota }
	return controller
}

func TestAccessStatePreservesLastSeenAndPrunesAfterRestart(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	peer := newPeerKey(t)
	lastSeen := now.Add(-49 * time.Hour)
	store := &memoryAccessStore{
		found: true,
		state: accessDiskState{
			Version: accessStateVersion,
			Peers: map[string]accessPeerState{
				peer.String(): {
					KeyID:     "open",
					CreatedAt: lastSeen,
					LastSeen:  lastSeen,
				},
			},
			Quotas: map[string]accessQuotaState{
				quotaOwner(peer, "open", ""): {
					UsageDate: now.Format(time.DateOnly),
					LastSeen:  lastSeen,
				},
			},
			IssueWindow: now,
			IssueCounts: map[string]int{},
		},
	}
	config := &testAccessConfig{now: now}
	controller := newTestController(store, newFakePeerDevice(), &fakeRevocationSource{}, config)
	if err := controller.load(); err != nil {
		t.Fatal(err)
	}
	if got := controller.peers[peer].LastSeen; !got.Equal(lastSeen) {
		t.Fatalf("lastSeen reset during load: got %v want %v", got, lastSeen)
	}
	if err := controller.reconcile(); err != nil {
		t.Fatal(err)
	}
	if _, ok := controller.peers[peer]; ok {
		t.Fatal("stale peer state survived pruning")
	}
	if _, ok := controller.quotas[quotaOwner(peer, "open", "")]; ok {
		t.Fatal("stale quota owner state survived pruning")
	}
}

func TestIncompleteUnifiedStateFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store := &memoryAccessStore{
		found: true,
		state: accessDiskState{
			Version:     accessStateVersion,
			IssueWindow: now,
			IssueCounts: map[string]int{},
			// A missing peers map is distinguishable from a legitimate empty map
			// and must not silently reset quota/auth state.
			Peers:  nil,
			Quotas: map[string]accessQuotaState{},
		},
	}
	controller := newTestController(store, newFakePeerDevice(), &fakeRevocationSource{}, &testAccessConfig{now: now})
	if err := controller.load(); err == nil {
		t.Fatal("incomplete state was accepted")
	}
}

func TestSecretRotationRejectsRestoreAndActivePeer(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	peer := newPeerKey(t)
	store := &memoryAccessStore{
		found: true,
		state: accessDiskState{
			Version: accessStateVersion,
			Peers: map[string]accessPeerState{
				peer.String(): {
					KeyID:          "issued-id",
					AuthGeneration: authGeneration("old-secret"),
					CreatedAt:      now.Add(-time.Hour),
					LastSeen:       now.Add(-time.Minute),
					Endpoint:       "192.0.2.10:1234",
					EndpointSeenAt: now.Add(-time.Minute),
				},
			},
			Quotas: map[string]accessQuotaState{
				quotaOwner(peer, "issued-id", authGeneration("old-secret")): {
					UsageDate: now.Format(time.DateOnly),
					LastSeen:  now.Add(-time.Minute),
				},
			},
			IssueWindow: now,
			IssueCounts: map[string]int{},
		},
	}
	device := newFakePeerDevice()
	device.setPeer(wgtypes.Peer{PublicKey: peer})
	config := &testAccessConfig{now: now, secret: "new-secret"}
	controller := newTestController(store, device, &fakeRevocationSource{}, config)
	if err := controller.load(); err != nil {
		t.Fatal(err)
	}
	if err := controller.restorePeers(); err != nil {
		t.Fatal(err)
	}
	if device.addCalls != 0 {
		t.Fatal("peer signed by old secret was restored")
	}
	if err := controller.reconcile(); err != nil {
		t.Fatal(err)
	}
	if device.removeCalls != 1 {
		t.Fatalf("old-generation active peer was not removed: calls=%d", device.removeCalls)
	}
}

func TestSharedKeyRotationRejectsRestoreAndActivePeer(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	peer := newPeerKey(t)
	oldGeneration := authGeneration("old-shared-key")
	store := &memoryAccessStore{
		found: true,
		state: accessDiskState{
			Version: accessStateVersion,
			Peers: map[string]accessPeerState{
				peer.String(): {
					KeyID:          "shared",
					AuthGeneration: oldGeneration,
					CreatedAt:      now.Add(-time.Hour),
					LastSeen:       now.Add(-time.Minute),
					Endpoint:       "192.0.2.10:1234",
					EndpointSeenAt: now.Add(-time.Minute),
				},
			},
			Quotas: map[string]accessQuotaState{
				quotaOwner(peer, "shared", oldGeneration): {
					UsageDate: now.Format(time.DateOnly),
					LastSeen:  now.Add(-time.Minute),
				},
			},
			IssueWindow: now,
			IssueCounts: map[string]int{},
		},
	}
	device := newFakePeerDevice()
	device.setPeer(wgtypes.Peer{PublicKey: peer})
	config := &testAccessConfig{now: now, legacyKey: "new-shared-key"}
	controller := newTestController(store, device, &fakeRevocationSource{}, config)
	if err := controller.load(); err != nil {
		t.Fatal(err)
	}
	if err := controller.restorePeers(); err != nil {
		t.Fatal(err)
	}
	if device.addCalls != 0 {
		t.Fatal("peer authorized by the old shared key was restored")
	}
	if err := controller.reconcile(); err != nil {
		t.Fatal(err)
	}
	if device.removeCalls != 1 {
		t.Fatalf("old shared-key peer was not removed: calls=%d", device.removeCalls)
	}
}

func TestCurrentGenerationPeerRestoresFromRecentEndpoint(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	peer := newPeerKey(t)
	store := &memoryAccessStore{
		found: true,
		state: accessDiskState{
			Version: accessStateVersion,
			Peers: map[string]accessPeerState{
				peer.String(): {
					KeyID:          "issued-id",
					AuthGeneration: authGeneration("secret"),
					CreatedAt:      now.Add(-time.Hour),
					LastSeen:       now.Add(-time.Minute),
					Endpoint:       "192.0.2.10:1234",
					EndpointSeenAt: now.Add(-time.Minute),
				},
			},
			Quotas: map[string]accessQuotaState{
				quotaOwner(peer, "issued-id", authGeneration("secret")): {
					UsageDate: now.Format(time.DateOnly),
					LastSeen:  now.Add(-time.Minute),
				},
			},
			IssueWindow: now,
			IssueCounts: map[string]int{},
		},
	}
	device := newFakePeerDevice()
	controller := newTestController(store, device, &fakeRevocationSource{}, &testAccessConfig{now: now, secret: "secret"})
	if err := controller.load(); err != nil {
		t.Fatal(err)
	}
	if err := controller.restorePeers(); err != nil {
		t.Fatal(err)
	}
	if device.addCalls != 1 {
		t.Fatalf("valid peer restore calls = %d", device.addCalls)
	}
}

func TestRegisterFailsBeforeDeviceMutationWhenStateWriteFails(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store := &memoryAccessStore{}
	device := newFakePeerDevice()
	config := &testAccessConfig{now: now}
	controller := newTestController(store, device, &fakeRevocationSource{}, config)
	if err := controller.load(); err != nil {
		t.Fatal(err)
	}
	store.saveErr = errors.New("disk full")
	peer := newPeerKey(t)
	if _, err := controller.registerPeer(peer, ""); !errors.Is(err, errAccessStateUnavailable) {
		t.Fatalf("register error = %v, want state unavailable", err)
	}
	if device.addCalls != 0 {
		t.Fatal("WireGuard peer mutated before durable state commit")
	}
	if _, ok := controller.peers[peer]; ok {
		t.Fatal("failed registration remained in memory")
	}
}

func TestRevocationReadFailureRemovesActiveIssuedPeer(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	peer := newPeerKey(t)
	store := &memoryAccessStore{
		found: true,
		state: accessDiskState{
			Version: accessStateVersion,
			Peers: map[string]accessPeerState{
				peer.String(): {
					KeyID:          "issued-id",
					AuthGeneration: authGeneration("secret"),
					CreatedAt:      now.Add(-time.Hour),
					LastSeen:       now,
				},
			},
			Quotas: map[string]accessQuotaState{
				quotaOwner(peer, "issued-id", authGeneration("secret")): {
					UsageDate: now.Format(time.DateOnly),
					LastSeen:  now,
				},
			},
			IssueWindow: now,
			IssueCounts: map[string]int{},
		},
	}
	device := newFakePeerDevice()
	device.setPeer(wgtypes.Peer{PublicKey: peer})
	revocations := &fakeRevocationSource{err: errors.New("permission denied")}
	config := &testAccessConfig{now: now, secret: "secret"}
	controller := newTestController(store, device, revocations, config)
	if err := controller.load(); err != nil {
		t.Fatal(err)
	}
	if err := controller.reconcile(); err != nil {
		t.Fatal(err)
	}
	if device.removeCalls != 1 {
		t.Fatalf("active issued peer remained after revocation read error: calls=%d", device.removeCalls)
	}
}

func TestQuotaBlockPersistsAndRemovalRetries(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	peer := newPeerKey(t)
	store := &memoryAccessStore{
		found: true,
		state: accessDiskState{
			Version: accessStateVersion,
			Peers: map[string]accessPeerState{
				peer.String(): {
					KeyID:     "open",
					CreatedAt: now.Add(-time.Hour),
					LastSeen:  now,
				},
			},
			Quotas: map[string]accessQuotaState{
				quotaOwner(peer, "open", ""): {
					UsageDate: now.Format(time.DateOnly),
					LastSeen:  now,
				},
			},
			IssueWindow: now,
			IssueCounts: map[string]int{},
		},
	}
	device := newFakePeerDevice()
	device.removeErr = errors.New("busy")
	device.setPeer(wgtypes.Peer{PublicKey: peer, ReceiveBytes: 60, TransmitBytes: 50})
	config := &testAccessConfig{now: now, quota: 100}
	controller := newTestController(store, device, &fakeRevocationSource{}, config)
	if err := controller.load(); err != nil {
		t.Fatal(err)
	}
	if err := controller.reconcile(); err != nil {
		t.Fatal(err)
	}
	blockedUntil := controller.quotas[quotaOwner(peer, "open", "")].BlockedUntil
	if !blockedUntil.Equal(nextLocalMidnight(now)) {
		t.Fatalf("blocked until %v, want %v", blockedUntil, nextLocalMidnight(now))
	}
	if _, err := controller.registerPeer(peer, ""); !errors.Is(err, errPeerBlocked) {
		t.Fatalf("blocked peer register error = %v", err)
	}
	device.removeErr = nil
	if err := controller.reconcile(); err != nil {
		t.Fatal(err)
	}
	if device.removeCalls != 2 {
		t.Fatalf("removal was not retried: calls=%d", device.removeCalls)
	}
	restarted := newTestController(store, newFakePeerDevice(), &fakeRevocationSource{}, config)
	if err := restarted.load(); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.registerPeer(peer, ""); !errors.Is(err, errPeerBlocked) {
		t.Fatalf("block did not survive restart: %v", err)
	}
}

func TestIssuedKeyQuotaAggregatesAcrossPeers(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store := &memoryAccessStore{}
	device := newFakePeerDevice()
	config := &testAccessConfig{now: now, secret: "secret", quota: 100}
	controller := newTestController(store, device, &fakeRevocationSource{}, config)
	if err := controller.load(); err != nil {
		t.Fatal(err)
	}

	peers := []wgtypes.Key{newPeerKey(t), newPeerKey(t), newPeerKey(t)}
	for _, peer := range peers {
		if _, err := controller.registerPeer(peer, "token:secret"); err != nil {
			t.Fatal(err)
		}
		device.setPeer(wgtypes.Peer{PublicKey: peer, ReceiveBytes: 40})
	}
	if err := controller.reconcile(); err != nil {
		t.Fatal(err)
	}

	owner := quotaOwner(peers[0], "issued-id", authGeneration("secret"))
	quota := controller.quotas[owner]
	if quota == nil || quota.UsedBytes != 120 {
		t.Fatalf("aggregate usage = %+v, want 120", quota)
	}
	if !quota.BlockedUntil.Equal(nextLocalMidnight(now)) {
		t.Fatalf("blocked until %v, want %v", quota.BlockedUntil, nextLocalMidnight(now))
	}
	if device.removeCalls != len(peers) {
		t.Fatalf("removed peers = %d, want %d", device.removeCalls, len(peers))
	}
	if _, err := controller.registerPeer(newPeerKey(t), "token:secret"); !errors.Is(err, errPeerBlocked) {
		t.Fatalf("new peer for blocked key error = %v", err)
	}

	restarted := newTestController(store, newFakePeerDevice(), &fakeRevocationSource{}, config)
	if err := restarted.load(); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.registerPeer(newPeerKey(t), "token:secret"); !errors.Is(err, errPeerBlocked) {
		t.Fatalf("aggregate key block did not survive restart: %v", err)
	}
}

func TestIssuedKeyActivePeerLimit(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store := &memoryAccessStore{}
	device := newFakePeerDevice()
	config := &testAccessConfig{now: now, secret: "secret"}
	controller := newTestController(store, device, &fakeRevocationSource{}, config)
	if err := controller.load(); err != nil {
		t.Fatal(err)
	}

	peers := make([]wgtypes.Key, maxActivePeersPerIssuedKey)
	for i := range peers {
		peers[i] = newPeerKey(t)
		if _, err := controller.registerPeer(peers[i], "token:secret"); err != nil {
			t.Fatalf("register peer %d: %v", i, err)
		}
	}
	if _, err := controller.registerPeer(newPeerKey(t), "token:secret"); !errors.Is(err, errPeerLimitReached) {
		t.Fatalf("peer above active limit error = %v", err)
	}
	if _, err := controller.registerPeer(peers[0], "token:secret"); err != nil {
		t.Fatalf("existing peer re-registration was counted as a new peer: %v", err)
	}
}

func TestChangingPeerKeyDoesNotEraseOriginalKeyUsage(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store := &memoryAccessStore{}
	device := newFakePeerDevice()
	config := &testAccessConfig{now: now, secret: "secret", quota: 100}
	controller := newTestController(store, device, &fakeRevocationSource{}, config)
	controller.validateKey = func(key string) (string, bool) {
		switch key {
		case "token-a":
			return "key-a", true
		case "token-b":
			return "key-b", true
		default:
			return "", false
		}
	}
	if err := controller.load(); err != nil {
		t.Fatal(err)
	}

	peer := newPeerKey(t)
	if _, err := controller.registerPeer(peer, "token-a"); err != nil {
		t.Fatal(err)
	}
	device.setPeer(wgtypes.Peer{PublicKey: peer, ReceiveBytes: 90})
	if err := controller.reconcile(); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.registerPeer(peer, "token-b"); err != nil {
		t.Fatal(err)
	}

	secondPeer := newPeerKey(t)
	if _, err := controller.registerPeer(secondPeer, "token-a"); err != nil {
		t.Fatal(err)
	}
	device.setPeer(wgtypes.Peer{PublicKey: secondPeer, ReceiveBytes: 11})
	if err := controller.reconcile(); err != nil {
		t.Fatal(err)
	}
	ownerA := quotaOwner(secondPeer, "key-a", authGeneration("secret"))
	if got := controller.quotas[ownerA].UsedBytes; got != 101 {
		t.Fatalf("original key usage = %d, want 101", got)
	}
	if _, err := controller.registerPeer(newPeerKey(t), "token-a"); !errors.Is(err, errPeerBlocked) {
		t.Fatalf("original key escaped quota after peer changed key: %v", err)
	}
}

func TestReregisterKeepsWireGuardCounterBaseline(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	peer := newPeerKey(t)
	store := &memoryAccessStore{
		found: true,
		state: accessDiskState{
			Version: accessStateVersion,
			Peers: map[string]accessPeerState{
				peer.String(): {
					KeyID:     "open",
					CreatedAt: now.Add(-time.Hour),
					LastSeen:  now,
				},
			},
			Quotas: map[string]accessQuotaState{
				quotaOwner(peer, "open", ""): {
					UsageDate: now.Format(time.DateOnly),
					LastSeen:  now,
				},
			},
			IssueWindow: now,
			IssueCounts: map[string]int{},
		},
	}
	device := newFakePeerDevice()
	device.setPeer(wgtypes.Peer{PublicKey: peer, ReceiveBytes: 100, TransmitBytes: 50})
	config := &testAccessConfig{now: now}
	controller := newTestController(store, device, &fakeRevocationSource{}, config)
	if err := controller.load(); err != nil {
		t.Fatal(err)
	}
	if err := controller.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := controller.quotas[quotaOwner(peer, "open", "")].UsedBytes; got != 150 {
		t.Fatalf("initial usage = %d", got)
	}
	if _, err := controller.registerPeer(peer, ""); err != nil {
		t.Fatal(err)
	}
	device.setPeer(wgtypes.Peer{PublicKey: peer, ReceiveBytes: 110, TransmitBytes: 55})
	if err := controller.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := controller.quotas[quotaOwner(peer, "open", "")].UsedBytes; got != 165 {
		t.Fatalf("usage after re-register = %d, want 165", got)
	}
}

func TestNeverHandshakenPeerIsPurgedByController(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store := &memoryAccessStore{}
	device := newFakePeerDevice()
	config := &testAccessConfig{now: now}
	controller := newTestController(store, device, &fakeRevocationSource{}, config)
	if err := controller.load(); err != nil {
		t.Fatal(err)
	}
	peer := newPeerKey(t)
	if _, err := controller.registerPeer(peer, ""); err != nil {
		t.Fatal(err)
	}
	config.now = now.Add(stalePeerMaxIdle + time.Minute)
	if err := controller.reconcile(); err != nil {
		t.Fatal(err)
	}
	if device.removeCalls != 1 {
		t.Fatalf("never-handshaken peer was not purged: calls=%d", device.removeCalls)
	}
}

func TestIssueLimitPersistsInUnifiedState(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store := &memoryAccessStore{}
	config := &testAccessConfig{now: now, secret: "secret"}
	controller := newTestController(store, newFakePeerDevice(), &fakeRevocationSource{}, config)
	if err := controller.load(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := controller.issueAuthKey("192.0.2.1", 5, 24*time.Hour); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}
	if _, err := controller.issueAuthKey("192.0.2.1", 5, 24*time.Hour); !errors.Is(err, errIssueRateLimited) {
		t.Fatalf("sixth issue error = %v", err)
	} else {
		var rateLimitErr *issueRateLimitError
		if !errors.As(err, &rateLimitErr) || rateLimitErr.retryAfter != 24*time.Hour {
			t.Fatalf("retry after = %v, want 24h", rateLimitErr)
		}
	}
	restarted := newTestController(store, newFakePeerDevice(), &fakeRevocationSource{}, config)
	if err := restarted.load(); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.issueAuthKey("192.0.2.1", 5, 24*time.Hour); !errors.Is(err, errIssueRateLimited) {
		t.Fatalf("issue limit reset across restart: %v", err)
	}
}

func TestMissingInitializedStateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	serverDir := filepath.Join(dir, "server")
	if err := os.MkdirAll(serverDir, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(serverDir, "access_state.json")
	markerPath := filepath.Join(serverDir, "access_state.initialized")
	if err := os.WriteFile(markerPath, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := fileAccessStateStore{
		statePath:  func() string { return statePath },
		markerPath: func() string { return markerPath },
	}
	if _, _, err := store.Load(); err == nil {
		t.Fatal("missing initialized access state was treated as first boot")
	}
}

func TestNextLocalMidnightUsesCalendarBoundary(t *testing.T) {
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("timezone data unavailable: %v", err)
	}
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, location)
	next := nextLocalMidnight(now)
	if next.Hour() != 0 || next.Day() != 2 {
		t.Fatalf("next midnight = %v", next)
	}
}
