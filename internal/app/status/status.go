package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"toktrail-collector/internal/local/statedir"
)

type Options struct {
	ServerURL  string
	HTTPClient *http.Client
}

type Result struct {
	State statedir.DeviceState
}

type selfResponse struct {
	Device struct {
		DeviceID          string    `json:"deviceId"`
		ApplicationID     string    `json:"applicationId"`
		ExternalSubjectID string    `json:"externalSubjectId"`
		DeviceName        string    `json:"deviceName"`
		Platform          string    `json:"platform"`
		ConsentRevision   int64     `json:"consentRevision"`
		UploadAuthorized  bool      `json:"uploadAuthorized"`
		PublicAuthorized  bool      `json:"publicAuthorized"`
		Revoked           bool      `json:"revoked"`
		CheckedAt         time.Time `json:"checkedAt"`
	} `json:"device"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func Run(ctx context.Context, store statedir.Store, opt Options) (Result, error) {
	st, err := store.Load()
	if err != nil {
		return Result{}, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return Result{}, errors.New("device is not bound; run toktrail bind first")
	}
	serverURL := strings.TrimSpace(opt.ServerURL)
	if serverURL == "" {
		serverURL = st.ServerURL
	}
	if serverURL == "" {
		serverURL = "http://127.0.0.1:3211"
	}
	endpoint, err := joinURL(serverURL, "/v1/devices/self")
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Authorization", "Bearer "+st.DeviceID+"."+st.DeviceSecret)
	client := opt.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	var body selfResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Result{}, err
	}
	if resp.StatusCode != http.StatusOK {
		if body.Error != nil {
			return Result{}, fmt.Errorf("status failed: %s: %s", body.Error.Code, body.Error.Message)
		}
		return Result{}, fmt.Errorf("status failed: status %d", resp.StatusCode)
	}
	if body.Device.DeviceID == "" {
		return Result{}, errors.New("status response missing deviceId")
	}
	st.ServerURL = strings.TrimRight(serverURL, "/")
	st.DeviceID = body.Device.DeviceID
	st.ApplicationID = body.Device.ApplicationID
	st.ExternalSubjectID = body.Device.ExternalSubjectID
	st.DeviceName = body.Device.DeviceName
	st.Platform = body.Device.Platform
	st.ConsentRevision = body.Device.ConsentRevision
	st.UploadAuthorized = body.Device.UploadAuthorized
	st.PublicAuthorized = body.Device.PublicAuthorized
	st.Revoked = body.Device.Revoked
	st.LastCheckedAt = body.Device.CheckedAt
	if err := store.Save(st); err != nil {
		return Result{}, err
	}
	return Result{State: st}, nil
}

func joinURL(base string, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("invalid server URL")
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}
