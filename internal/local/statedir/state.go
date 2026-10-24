package statedir

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const stateFileName = "device.json"

type DeviceState struct {
	ServerURL               string    `json:"serverUrl,omitempty"`
	ApplicationID           string    `json:"applicationId,omitempty"`
	ExternalSubjectID       string    `json:"externalSubjectId,omitempty"`
	DeviceID                string    `json:"deviceId,omitempty"`
	DeviceName              string    `json:"deviceName,omitempty"`
	Platform                string    `json:"platform,omitempty"`
	DeviceSecret            string    `json:"deviceSecret,omitempty"`
	BindRequestID           string    `json:"bindRequestId,omitempty"`
	ConsentRevision         int64     `json:"consentRevision,omitempty"`
	BoundAt                 time.Time `json:"boundAt,omitempty"`
	UploadAuthorized        bool      `json:"uploadAuthorized"`
	PublicAuthorized        bool      `json:"publicAuthorized"`
	Revoked                 bool      `json:"revoked"`
	LastCheckedAt           time.Time `json:"lastCheckedAt,omitempty"`
	LastSyncedAt            time.Time `json:"lastSyncedAt,omitempty"`
	LastSyncBatchID         string    `json:"lastSyncBatchId,omitempty"`
	LastSyncStatus          string    `json:"lastSyncStatus,omitempty"`
	LastSyncAcceptedRecords int       `json:"lastSyncAcceptedRecords"`
	LastSyncRejectedRecords int       `json:"lastSyncRejectedRecords"`
	UpdatedAt               time.Time `json:"updatedAt,omitempty"`
}

type Store struct{ dir string }

func New(dir string) Store { return Store{dir: strings.TrimSpace(dir)} }

func DefaultDir() (string, error) {
	if v := strings.TrimSpace(os.Getenv("TOKTRAIL_HOME")); v != "" {
		return v, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "toktrail"), nil
}

func (s Store) Path() string { return filepath.Join(s.dir, stateFileName) }

func (s Store) Load() (DeviceState, error) {
	b, err := os.ReadFile(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return DeviceState{}, nil
	}
	if err != nil {
		return DeviceState{}, err
	}
	var st DeviceState
	if err := json.Unmarshal(b, &st); err != nil {
		return DeviceState{}, err
	}
	return st, nil
}

func (s Store) Save(st DeviceState) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	st.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path())
}
