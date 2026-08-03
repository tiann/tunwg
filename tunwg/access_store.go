package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ntnj/tunwg/internal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wireGuardPeerDevice struct{}

func (wireGuardPeerDevice) AddPeer(peer wgtypes.Key, endpoint string) error {
	return allowUserKey(peer, endpoint)
}

func (wireGuardPeerDevice) RemovePeer(peer wgtypes.Key) error {
	return internal.RemovePeer(peer)
}

func (wireGuardPeerDevice) Snapshot() (*wgtypes.Device, error) {
	return internal.GetWgDeviceInfo()
}

type fileRevocationSource struct {
	path func() string
}

func (s fileRevocationSource) Load() (map[string]bool, error) {
	data, err := os.ReadFile(s.path())
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]bool), nil
		}
		return nil, err
	}
	revoked := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		if id := strings.TrimSpace(line); id != "" {
			revoked[id] = true
		}
	}
	return revoked, nil
}

type fileAccessStateStore struct {
	statePath  func() string
	markerPath func() string
}

func (s fileAccessStateStore) Load() (accessDiskState, bool, error) {
	state := accessDiskState{
		Version:     accessStateVersion,
		Peers:       make(map[string]accessPeerState),
		Quotas:      make(map[string]accessQuotaState),
		IssueCounts: make(map[string]int),
	}
	data, err := os.ReadFile(s.statePath())
	if err == nil {
		if err := json.Unmarshal(data, &state); err != nil {
			return accessDiskState{}, false, err
		}
		if state.Version == 0 {
			return accessDiskState{}, false, errors.New("access state has no version")
		}
		return state, true, nil
	} else if !os.IsNotExist(err) {
		return accessDiskState{}, false, err
	}
	if s.markerPath != nil {
		if _, err := os.Stat(s.markerPath()); err == nil {
			return accessDiskState{}, false, errors.New("access state is missing after initialization")
		} else if !os.IsNotExist(err) {
			return accessDiskState{}, false, err
		}
	}

	return state, false, nil
}

func (s fileAccessStateStore) Save(state accessDiskState) error {
	path := s.statePath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	writeErr := error(nil)
	if err := file.Chmod(0o600); err != nil {
		writeErr = err
	} else if _, err := file.Write(data); err != nil {
		writeErr = err
	} else if err := file.Sync(); err != nil {
		writeErr = err
	}
	if err := file.Close(); writeErr == nil && err != nil {
		writeErr = err
	}
	if writeErr != nil {
		return writeErr
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return s.ensureMarker(dir)
}

func (s fileAccessStateStore) ensureMarker(dir string) error {
	if s.markerPath == nil {
		return nil
	}
	marker := s.markerPath()
	if data, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(data)) == fmt.Sprint(accessStateVersion) {
		return nil
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	writeErr := error(nil)
	if err := file.Chmod(0o600); err != nil {
		writeErr = err
	} else if _, err := fmt.Fprintf(file, "%d\n", accessStateVersion); err != nil {
		writeErr = err
	} else if err := file.Sync(); err != nil {
		writeErr = err
	}
	if err := file.Close(); writeErr == nil && err != nil {
		writeErr = err
	}
	if writeErr != nil {
		return writeErr
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func accessStatePath() string {
	return filepath.Join(internal.Keystorage(), "server", "access_state.json")
}

func accessStateMarkerPath() string {
	return filepath.Join(internal.Keystorage(), "server", "access_state.initialized")
}

func revocationStatePath() string {
	return filepath.Join(internal.Keystorage(), "server", "revoked_keys")
}

var globalAccess = newAccessController(
	fileAccessStateStore{
		statePath:  accessStatePath,
		markerPath: accessStateMarkerPath,
	},
	wireGuardPeerDevice{},
	fileRevocationSource{path: revocationStatePath},
)
