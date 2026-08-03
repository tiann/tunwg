package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/ntnj/tunwg/internal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	accessStateVersion           = 2
	peerStateRetention           = 48 * time.Hour
	restoreEndpointMaxAge        = 15 * time.Minute
	stalePeerMaxIdle             = 30 * time.Minute
	maxActivePeersPerIssuedKey   = 3
	defaultIssueLimitPerIPPerDay = 20
)

var (
	errAccessUnauthorized     = errors.New("access unauthorized")
	errRevocationsUnavailable = errors.New("revocation state unavailable")
	errPeerBlocked            = errors.New("peer blocked")
	errPeerLimitReached       = errors.New("peer limit reached")
	errIssueRateLimited       = errors.New("issue rate limited")
	errAccessStateUnavailable = errors.New("access state unavailable")
)

type issueRateLimitError struct {
	retryAfter time.Duration
}

func (e *issueRateLimitError) Error() string {
	return errIssueRateLimited.Error()
}

func (e *issueRateLimitError) Unwrap() error {
	return errIssueRateLimited
}

type accessPeerState struct {
	KeyID          string    `json:"key_id,omitempty"`
	AuthGeneration string    `json:"auth_generation,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	LastSeen       time.Time `json:"last_seen"`
	Endpoint       string    `json:"endpoint,omitempty"`
	EndpointSeenAt time.Time `json:"endpoint_seen_at,omitempty"`
}

type accessQuotaState struct {
	UsageDate    string    `json:"usage_date"`
	UsedBytes    int64     `json:"used_bytes,omitempty"`
	BlockedUntil time.Time `json:"blocked_until,omitempty"`
	LastSeen     time.Time `json:"last_seen"`
}

type accessDiskState struct {
	Version     int                         `json:"version"`
	Peers       map[string]accessPeerState  `json:"peers"`
	Quotas      map[string]accessQuotaState `json:"quotas"`
	IssueWindow time.Time                   `json:"issue_window"`
	IssueCounts map[string]int              `json:"issue_counts"`
}

type accessStateStore interface {
	Load() (accessDiskState, bool, error)
	Save(accessDiskState) error
}

type peerDevice interface {
	AddPeer(wgtypes.Key, string) error
	RemovePeer(wgtypes.Key) error
	Snapshot() (*wgtypes.Device, error)
}

type revocationSource interface {
	Load() (map[string]bool, error)
}

type peerRuntime struct {
	lastRx, lastTx int64
	addedAt        time.Time
}

type accessController struct {
	mu sync.Mutex

	peers       map[wgtypes.Key]*accessPeerState
	quotas      map[string]*accessQuotaState
	runtime     map[wgtypes.Key]*peerRuntime
	issueWindow time.Time
	issueCounts map[string]int
	stateErr    error
	failures    chan error

	store       accessStateStore
	device      peerDevice
	revocations revocationSource
	now         func() time.Time
	authSecret  func() string
	legacyKey   func() string
	validateKey func(string) (string, bool)
	issueKey    func() (string, error)
	quotaBytes  func() int64
}

func newAccessController(store accessStateStore, device peerDevice, revocations revocationSource) *accessController {
	return &accessController{
		peers:       make(map[wgtypes.Key]*accessPeerState),
		quotas:      make(map[string]*accessQuotaState),
		runtime:     make(map[wgtypes.Key]*peerRuntime),
		issueCounts: make(map[string]int),
		failures:    make(chan error, 1),
		store:       store,
		device:      device,
		revocations: revocations,
		now:         time.Now,
		authSecret:  internal.AuthSecret,
		legacyKey:   internal.AuthKey,
		validateKey: internal.ValidateAuthKey,
		issueKey:    internal.IssueAuthKey,
		quotaBytes:  internal.QuotaBytes,
	}
}

func authGeneration(secret string) string {
	if secret == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:16])
}

func (c *accessController) load() error {
	state, found, err := c.store.Load()
	if err != nil {
		return fmt.Errorf("load access state: %w", err)
	}
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.peers = make(map[wgtypes.Key]*accessPeerState)
	c.quotas = make(map[string]*accessQuotaState)
	c.runtime = make(map[wgtypes.Key]*peerRuntime)
	c.issueCounts = make(map[string]int)
	c.stateErr = nil
	drainingFailures := true
	for drainingFailures {
		select {
		case <-c.failures:
		default:
			drainingFailures = false
		}
	}

	if found {
		if state.Version != accessStateVersion {
			return fmt.Errorf("unsupported access state version %d", state.Version)
		}
		if state.Peers == nil || state.Quotas == nil || state.IssueCounts == nil || state.IssueWindow.IsZero() {
			return errors.New("access state is missing required fields")
		}
		for owner, saved := range state.Quotas {
			if owner == "" {
				return errors.New("access state contains an empty quota owner")
			}
			record := saved
			if record.UsedBytes < 0 {
				return fmt.Errorf("negative usage for quota owner %q", owner)
			}
			if _, err := time.Parse(time.DateOnly, record.UsageDate); err != nil {
				return fmt.Errorf("invalid usage date for quota owner %q: %w", owner, err)
			}
			if record.LastSeen.IsZero() {
				return fmt.Errorf("missing last-seen timestamp for quota owner %q", owner)
			}
			normalizeQuotaState(&record, now)
			c.quotas[owner] = &record
		}
		for encoded, saved := range state.Peers {
			key, err := wgtypes.ParseKey(encoded)
			if err != nil {
				return fmt.Errorf("invalid peer key %q in access state: %w", encoded, err)
			}
			record := saved
			if record.KeyID == "" {
				return fmt.Errorf("missing key id for peer %s", encoded)
			}
			if record.KeyID == "open" && record.AuthGeneration != "" {
				return fmt.Errorf("open peer %s has an auth generation", encoded)
			}
			if record.KeyID != "open" && record.AuthGeneration == "" {
				return fmt.Errorf("missing auth generation for peer %s", encoded)
			}
			if record.CreatedAt.IsZero() || record.LastSeen.IsZero() {
				return fmt.Errorf("missing lifecycle timestamps for peer %s", encoded)
			}
			if record.Endpoint != "" && record.EndpointSeenAt.IsZero() {
				return fmt.Errorf("missing endpoint timestamp for peer %s", encoded)
			}
			owner := quotaOwner(key, record.KeyID, record.AuthGeneration)
			if c.quotas[owner] == nil {
				return fmt.Errorf("peer %s has no quota owner state", encoded)
			}
			c.peers[key] = &record
		}
		c.issueWindow = state.IssueWindow
		for ip, count := range state.IssueCounts {
			if count < 0 {
				return fmt.Errorf("negative issue count for %s", ip)
			}
			if count > 0 {
				c.issueCounts[ip] = count
			}
		}
	}
	if c.issueWindow.IsZero() || now.Sub(c.issueWindow) >= 24*time.Hour || now.Before(c.issueWindow) {
		c.issueWindow = now
		c.issueCounts = make(map[string]int)
	}
	if err := c.persistLocked(); err != nil {
		return err
	}
	return nil
}

func (c *accessController) diskStateLocked() accessDiskState {
	state := accessDiskState{
		Version:     accessStateVersion,
		Peers:       make(map[string]accessPeerState, len(c.peers)),
		Quotas:      make(map[string]accessQuotaState, len(c.quotas)),
		IssueWindow: c.issueWindow,
		IssueCounts: make(map[string]int, len(c.issueCounts)),
	}
	for key, record := range c.peers {
		state.Peers[key.String()] = *record
	}
	for owner, record := range c.quotas {
		state.Quotas[owner] = *record
	}
	for ip, count := range c.issueCounts {
		state.IssueCounts[ip] = count
	}
	return state
}

func (c *accessController) persistLocked() error {
	if c.stateErr != nil {
		return c.stateErr
	}
	if err := c.store.Save(c.diskStateLocked()); err != nil {
		c.stateErr = fmt.Errorf("%w: %v", errAccessStateUnavailable, err)
		select {
		case c.failures <- c.stateErr:
		default:
		}
		return c.stateErr
	}
	return nil
}

func cloneAccessPeer(record *accessPeerState) *accessPeerState {
	if record == nil {
		return nil
	}
	copy := *record
	return &copy
}

func cloneAccessQuota(record *accessQuotaState) *accessQuotaState {
	if record == nil {
		return nil
	}
	copy := *record
	return &copy
}

func (c *accessController) restoreRecordLocked(peer wgtypes.Key, old *accessPeerState) {
	if old == nil {
		delete(c.peers, peer)
		return
	}
	c.peers[peer] = old
}

func (c *accessController) restoreQuotaLocked(owner string, old *accessQuotaState) {
	if old == nil {
		delete(c.quotas, owner)
		return
	}
	c.quotas[owner] = old
}

func quotaOwner(peer wgtypes.Key, keyID, generation string) string {
	if keyID == "open" {
		return "peer:" + peer.String()
	}
	return "key:" + generation + ":" + keyID
}

func normalizeQuotaState(record *accessQuotaState, now time.Time) {
	if record.UsageDate != now.Format(time.DateOnly) {
		record.UsageDate = now.Format(time.DateOnly)
		record.UsedBytes = 0
		record.BlockedUntil = time.Time{}
	} else if !record.BlockedUntil.IsZero() && !now.Before(record.BlockedUntil) {
		record.BlockedUntil = time.Time{}
	}
}

func addUsage(current, delta int64) int64 {
	if delta <= 0 {
		return current
	}
	if current > math.MaxInt64-delta {
		return math.MaxInt64
	}
	return current + delta
}

type peerCredential struct {
	keyID          string
	authGeneration string
}

func (c *accessController) authorizeLocked(reqKey string) (peerCredential, error) {
	if secret := c.authSecret(); secret != "" {
		id, valid := c.validateKey(reqKey)
		if !valid {
			return peerCredential{}, errAccessUnauthorized
		}
		credential := peerCredential{keyID: id, authGeneration: authGeneration(secret)}
		revoked, err := c.revocations.Load()
		if err != nil {
			return credential, fmt.Errorf("%w: %v", errRevocationsUnavailable, err)
		}
		if revoked[id] {
			return credential, errAccessUnauthorized
		}
		return credential, nil
	}
	if legacy := c.legacyKey(); legacy != "" {
		if reqKey != legacy {
			return peerCredential{}, errAccessUnauthorized
		}
		return peerCredential{keyID: "shared", authGeneration: authGeneration(legacy)}, nil
	}
	return peerCredential{keyID: "open"}, nil
}

func (c *accessController) credentialMatchesCurrentModeLocked(credential peerCredential) bool {
	if secret := c.authSecret(); secret != "" {
		return credential.keyID != "" && credential.keyID != "open" && credential.keyID != "shared" && credential.authGeneration == authGeneration(secret)
	}
	if c.legacyKey() != "" {
		return credential.keyID == "shared" && credential.authGeneration == authGeneration(c.legacyKey())
	}
	return credential.keyID == "open" && credential.authGeneration == ""
}

func (c *accessController) recordMatchesCurrentModeLocked(record *accessPeerState) bool {
	if record == nil {
		return false
	}
	if secret := c.authSecret(); secret != "" {
		return record.KeyID != "" && record.KeyID != "open" && record.KeyID != "shared" && record.AuthGeneration == authGeneration(secret)
	}
	if c.legacyKey() != "" {
		return record.KeyID == "shared" && record.AuthGeneration == authGeneration(c.legacyKey())
	}
	return true
}

func (c *accessController) registerPeer(peer wgtypes.Key, reqKey string) (peerCredential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stateErr != nil {
		return peerCredential{}, c.stateErr
	}
	credential, err := c.authorizeLocked(reqKey)
	if err != nil {
		return credential, err
	}
	if !c.credentialMatchesCurrentModeLocked(credential) {
		return peerCredential{}, errAccessUnauthorized
	}
	now := c.now()
	limit := c.quotaBytes()
	owner := quotaOwner(peer, credential.keyID, credential.authGeneration)
	oldQuota := cloneAccessQuota(c.quotas[owner])
	quota := cloneAccessQuota(oldQuota)
	if quota == nil {
		quota = &accessQuotaState{UsageDate: now.Format(time.DateOnly), LastSeen: now}
	}
	normalizeQuotaState(quota, now)
	if now.Before(quota.BlockedUntil) || (limit > 0 && quota.UsedBytes > limit) {
		return credential, errPeerBlocked
	}
	if credential.keyID != "open" && credential.keyID != "shared" {
		activePeers := 0
		for activePeer := range c.runtime {
			if activePeer == peer {
				continue
			}
			record := c.peers[activePeer]
			if record != nil && quotaOwner(activePeer, record.KeyID, record.AuthGeneration) == owner {
				activePeers++
			}
		}
		if activePeers >= maxActivePeersPerIssuedKey {
			return credential, errPeerLimitReached
		}
	}
	old := cloneAccessPeer(c.peers[peer])
	record := cloneAccessPeer(old)
	if record == nil {
		record = &accessPeerState{CreatedAt: now}
	}
	record.KeyID = credential.keyID
	record.AuthGeneration = credential.authGeneration
	record.LastSeen = now
	quota.LastSeen = now
	c.peers[peer] = record
	c.quotas[owner] = quota
	if err := c.persistLocked(); err != nil {
		c.restoreRecordLocked(peer, old)
		c.restoreQuotaLocked(owner, oldQuota)
		return credential, err
	}
	if err := c.device.AddPeer(peer, ""); err != nil {
		if cleanupErr := c.device.RemovePeer(peer); cleanupErr != nil {
			// The device may have applied part of the add. Keep the durable
			// authorization record so any possibly-active peer still has a
			// controller-owned identity and will be reconciled on the next tick.
			if runtime := c.runtime[peer]; runtime == nil {
				c.runtime[peer] = &peerRuntime{addedAt: now}
			} else {
				runtime.addedAt = now
			}
			return credential, fmt.Errorf("add WireGuard peer: %w (cleanup: %v)", err, cleanupErr)
		}
		c.restoreRecordLocked(peer, old)
		c.restoreQuotaLocked(owner, oldQuota)
		delete(c.runtime, peer)
		if rollbackErr := c.persistLocked(); rollbackErr != nil {
			return credential, rollbackErr
		}
		return credential, fmt.Errorf("add WireGuard peer: %w", err)
	}
	if runtime := c.runtime[peer]; runtime == nil {
		c.runtime[peer] = &peerRuntime{addedAt: now}
	} else {
		// Re-registering an existing peer must not reset its counter baseline;
		// WireGuard normally preserves counters when updating that peer.
		runtime.addedAt = now
	}
	return credential, nil
}

func (c *accessController) issueAuthKey(ip string, max int, window time.Duration) (string, error) {
	secret := c.authSecret()
	if secret == "" {
		return "", errAccessUnauthorized
	}
	key, err := c.issueKey()
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stateErr != nil {
		return "", c.stateErr
	}
	if authGeneration(c.authSecret()) != authGeneration(secret) {
		return "", errAccessUnauthorized
	}
	now := c.now()
	if c.issueWindow.IsZero() || now.Sub(c.issueWindow) >= window || now.Before(c.issueWindow) {
		c.issueWindow = now
		c.issueCounts = make(map[string]int)
	}
	if c.issueCounts[ip] >= max {
		retryAfter := c.issueWindow.Add(window).Sub(now)
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return "", &issueRateLimitError{retryAfter: retryAfter}
	}
	c.issueCounts[ip]++
	if err := c.persistLocked(); err != nil {
		c.issueCounts[ip]--
		return "", err
	}
	return key, nil
}

func (c *accessController) restorePeers() error {
	now := c.now()
	limit := c.quotaBytes()
	var revoked map[string]bool
	var revocationErr error
	if c.authSecret() != "" {
		revoked, revocationErr = c.revocations.Load()
		if revocationErr != nil {
			slog.Error("revocation state unavailable; persisted peers will not be restored", "err", revocationErr)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stateErr != nil {
		return c.stateErr
	}
	changed := false
	for peer, record := range c.peers {
		if record.Endpoint == "" || record.EndpointSeenAt.IsZero() || now.Sub(record.EndpointSeenAt) >= restoreEndpointMaxAge || now.Before(record.EndpointSeenAt) {
			if record.Endpoint != "" || !record.EndpointSeenAt.IsZero() {
				record.Endpoint = ""
				record.EndpointSeenAt = time.Time{}
				changed = true
			}
			continue
		}
		owner := quotaOwner(peer, record.KeyID, record.AuthGeneration)
		quota := c.quotas[owner]
		if quota == nil {
			return fmt.Errorf("peer %s has no quota owner state", peer.String())
		}
		normalizeQuotaState(quota, now)
		if limit > 0 && quota.UsedBytes > limit && !now.Before(quota.BlockedUntil) {
			quota.BlockedUntil = nextLocalMidnight(now)
			changed = true
		}
		if now.Before(quota.BlockedUntil) {
			continue
		}
		if !c.recordMatchesCurrentModeLocked(record) {
			record.Endpoint = ""
			record.EndpointSeenAt = time.Time{}
			changed = true
			continue
		}
		if c.authSecret() != "" {
			if revocationErr != nil {
				continue
			}
			if revoked[record.KeyID] {
				record.Endpoint = ""
				record.EndpointSeenAt = time.Time{}
				changed = true
				continue
			}
		}
		if err := c.device.AddPeer(peer, record.Endpoint); err != nil {
			slog.Warn("failed to restore peer", "peer", peer.String(), "err", err)
			record.Endpoint = ""
			record.EndpointSeenAt = time.Time{}
			changed = true
			continue
		}
		c.runtime[peer] = &peerRuntime{addedAt: now}
	}
	if changed {
		return c.persistLocked()
	}
	return nil
}

type peerRemoval struct {
	key    wgtypes.Key
	reason string
}

func nextLocalMidnight(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).AddDate(0, 0, 1)
}

func (c *accessController) reconcile() error {
	device, err := c.device.Snapshot()
	if err != nil {
		return fmt.Errorf("read WireGuard peers: %w", err)
	}
	now := c.now()
	today := now.Format(time.DateOnly)
	limit := c.quotaBytes()
	secretMode := c.authSecret() != ""
	var revoked map[string]bool
	var revocationErr error
	if secretMode {
		revoked, revocationErr = c.revocations.Load()
		if revocationErr != nil {
			slog.Error("revocation state unavailable; removing issued-key peers", "err", revocationErr)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stateErr != nil {
		return c.stateErr
	}
	active := make(map[wgtypes.Key]bool, len(device.Peers))
	removals := make([]peerRemoval, 0)
	unauthorized := make(map[wgtypes.Key]bool)
	for _, peer := range device.Peers {
		active[peer.PublicKey] = true
		record := c.peers[peer.PublicKey]
		if record == nil {
			if secretMode || c.legacyKey() != "" {
				removals = append(removals, peerRemoval{peer.PublicKey, "unauthorized"})
				unauthorized[peer.PublicKey] = true
				continue
			}
			record = &accessPeerState{
				KeyID:     "open",
				CreatedAt: now,
				LastSeen:  now,
			}
			c.peers[peer.PublicKey] = record
		}
		owner := quotaOwner(peer.PublicKey, record.KeyID, record.AuthGeneration)
		quota := c.quotas[owner]
		if quota == nil {
			if record.KeyID != "open" {
				return fmt.Errorf("peer %s has no quota owner state", peer.PublicKey.String())
			}
			quota = &accessQuotaState{UsageDate: today, LastSeen: now}
			c.quotas[owner] = quota
		}
		normalizeQuotaState(quota, now)
		runtime := c.runtime[peer.PublicKey]
		if runtime == nil {
			runtime = &peerRuntime{addedAt: now}
			c.runtime[peer.PublicKey] = runtime
		}
		drx := peer.ReceiveBytes - runtime.lastRx
		dtx := peer.TransmitBytes - runtime.lastTx
		if drx < 0 {
			drx = peer.ReceiveBytes
		}
		if dtx < 0 {
			dtx = peer.TransmitBytes
		}
		runtime.lastRx, runtime.lastTx = peer.ReceiveBytes, peer.TransmitBytes
		quota.UsedBytes = addUsage(addUsage(quota.UsedBytes, drx), dtx)
		quota.LastSeen = now
		record.LastSeen = now
		if !peer.LastHandshakeTime.IsZero() && now.Sub(peer.LastHandshakeTime) < restoreEndpointMaxAge && peer.Endpoint != nil {
			record.Endpoint = peer.Endpoint.String()
			record.EndpointSeenAt = peer.LastHandshakeTime
		} else if !peer.LastHandshakeTime.IsZero() && now.Sub(peer.LastHandshakeTime) >= restoreEndpointMaxAge {
			record.Endpoint = ""
			record.EndpointSeenAt = time.Time{}
		} else if peer.LastHandshakeTime.IsZero() && now.Sub(runtime.addedAt) >= restoreEndpointMaxAge {
			record.Endpoint = ""
			record.EndpointSeenAt = time.Time{}
		}
	}

	blockedOwners := make(map[string]bool)
	if limit > 0 {
		for _, peer := range device.Peers {
			record := c.peers[peer.PublicKey]
			if record == nil {
				continue
			}
			owner := quotaOwner(peer.PublicKey, record.KeyID, record.AuthGeneration)
			quota := c.quotas[owner]
			if quota == nil || quota.UsedBytes <= limit || now.Before(quota.BlockedUntil) {
				continue
			}
			quota.BlockedUntil = nextLocalMidnight(now)
			if !blockedOwners[owner] {
				blockedOwners[owner] = true
				slog.Warn("quota exceeded, quota owner blocked until next day",
					"key_id", record.KeyID, "used_today", quota.UsedBytes, "limit", limit)
			}
		}
	}

	for _, peer := range device.Peers {
		if unauthorized[peer.PublicKey] {
			continue
		}
		record := c.peers[peer.PublicKey]
		if record == nil {
			continue
		}
		quota := c.quotas[quotaOwner(peer.PublicKey, record.KeyID, record.AuthGeneration)]
		if quota == nil {
			return fmt.Errorf("peer %s has no quota owner state", peer.PublicKey.String())
		}
		runtime := c.runtime[peer.PublicKey]
		reason := ""
		switch {
		case !c.recordMatchesCurrentModeLocked(record):
			reason = "unauthorized"
		case secretMode && revocationErr != nil:
			reason = "revocation-unavailable"
		case secretMode && revoked[record.KeyID]:
			reason = "revoked"
		case now.Before(quota.BlockedUntil):
			reason = "quota"
		case peer.LastHandshakeTime.IsZero() && now.Sub(runtime.addedAt) >= stalePeerMaxIdle:
			reason = "stale"
		case !peer.LastHandshakeTime.IsZero() && now.Sub(peer.LastHandshakeTime) >= stalePeerMaxIdle:
			reason = "stale"
		}
		if reason != "" {
			record.Endpoint = ""
			record.EndpointSeenAt = time.Time{}
			removals = append(removals, peerRemoval{peer.PublicKey, reason})
		}
	}
	for peer, record := range c.peers {
		if active[peer] {
			continue
		}
		if now.Sub(record.LastSeen) >= peerStateRetention {
			delete(c.peers, peer)
			delete(c.runtime, peer)
		}
	}
	referencedOwners := make(map[string]bool, len(c.peers))
	for peer, record := range c.peers {
		referencedOwners[quotaOwner(peer, record.KeyID, record.AuthGeneration)] = true
	}
	for owner, quota := range c.quotas {
		if !referencedOwners[owner] && now.Sub(quota.LastSeen) >= peerStateRetention && !now.Before(quota.BlockedUntil) {
			delete(c.quotas, owner)
		}
	}
	if err := c.persistLocked(); err != nil {
		return err
	}
	for _, removal := range removals {
		if err := c.device.RemovePeer(removal.key); err != nil {
			slog.Warn("failed to remove peer", "peer", removal.key.String(), "reason", removal.reason, "err", err)
			continue
		}
		slog.Info("removed peer", "peer", removal.key.String(), "reason", removal.reason)
		delete(c.runtime, removal.key)
	}
	return nil
}

func (c *accessController) run(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case err := <-c.failures:
			fatal("access controller failed closed", "err", err)
		case <-ticker.C:
			if err := c.reconcile(); err != nil {
				fatal("access controller failed closed", "err", err)
			}
		}
	}
}
