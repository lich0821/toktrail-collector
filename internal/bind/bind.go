package bind

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"toktrail-collector/internal/local/statedir"
)

type Options struct {
	ServerURL         string
	Ticket            string
	ApplicationID     string
	ExternalSubjectID string
	DeviceName        string
	Platform          string
	HTTPClient        *http.Client
	Now               func() time.Time
}

type Result struct {
	State  statedir.DeviceState
	Replay bool
	Status int
}

type bindRequest struct {
	RequestID         string `json:"requestId"`
	Ticket            string `json:"ticket"`
	ApplicationID     string `json:"applicationId"`
	ExternalSubjectID string `json:"externalSubjectId"`
	DeviceName        string `json:"deviceName"`
	Platform          string `json:"platform"`
	DeviceSecret      string `json:"deviceSecret"`
}

type bindResponse struct {
	Device struct {
		DeviceID          string    `json:"deviceId"`
		ApplicationID     string    `json:"applicationId"`
		ExternalSubjectID string    `json:"externalSubjectId"`
		DeviceName        string    `json:"deviceName"`
		Platform          string    `json:"platform"`
		ConsentRevision   int64     `json:"consentRevision"`
		BoundAt           time.Time `json:"boundAt"`
		Replay            bool      `json:"replay"`
	} `json:"device"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func Run(ctx context.Context, store statedir.Store, opt Options) (Result, error) {
	opt = opt.withDefaults()
	if err := opt.validate(); err != nil {
		return Result{}, err
	}
	st, err := store.Load()
	if err != nil {
		return Result{}, err
	}
	if st.DeviceSecret == "" {
		st.DeviceSecret, err = randomHex(32)
		if err != nil {
			return Result{}, err
		}
	}
	// Reuse the idempotency request ID only while the first bind is still
	// unconfirmed. Once a device receipt has been persisted, a later setup run
	// uses a fresh single-use ticket and therefore a different payload; reusing
	// the old request ID would correctly trip the server's idempotency conflict.
	if st.BindRequestID == "" || st.DeviceID != "" {
		st.BindRequestID, err = randomHex(16)
		if err != nil {
			return Result{}, err
		}
	}
	request := bindRequest{
		RequestID:         st.BindRequestID,
		Ticket:            opt.Ticket,
		ApplicationID:     opt.ApplicationID,
		ExternalSubjectID: opt.ExternalSubjectID,
		DeviceName:        opt.DeviceName,
		Platform:          opt.Platform,
		DeviceSecret:      st.DeviceSecret,
	}
	endpoint, err := joinURL(opt.ServerURL, "/v1/devices/bind")
	if err != nil {
		return Result{}, err
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := opt.HTTPClient
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	var body bindResponse
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&body); err != nil {
		return Result{}, err
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		if body.Error != nil {
			return Result{}, fmt.Errorf("bind failed: %s: %s", body.Error.Code, body.Error.Message)
		}
		return Result{}, fmt.Errorf("bind failed: status %d", resp.StatusCode)
	}
	if body.Device.DeviceID == "" {
		return Result{}, errors.New("bind response missing deviceId")
	}
	st.ServerURL = strings.TrimRight(opt.ServerURL, "/")
	st.ApplicationID = body.Device.ApplicationID
	st.ExternalSubjectID = body.Device.ExternalSubjectID
	st.DeviceID = body.Device.DeviceID
	st.DeviceName = body.Device.DeviceName
	st.Platform = body.Device.Platform
	st.ConsentRevision = body.Device.ConsentRevision
	st.BoundAt = body.Device.BoundAt
	if err := store.Save(st); err != nil {
		return Result{}, err
	}
	return Result{State: st, Replay: body.Device.Replay, Status: resp.StatusCode}, nil
}

func (o Options) withDefaults() Options {
	o.ServerURL = strings.TrimSpace(o.ServerURL)
	if o.ServerURL == "" {
		o.ServerURL = "http://127.0.0.1:3211"
	}
	o.ApplicationID = strings.TrimSpace(o.ApplicationID)
	if o.ApplicationID == "" {
		o.ApplicationID = "leaderboard-local"
	}
	o.ExternalSubjectID = strings.TrimSpace(o.ExternalSubjectID)
	o.DeviceName = strings.TrimSpace(o.DeviceName)
	if o.DeviceName == "" {
		o.DeviceName = "toktrail-collector"
	}
	o.Platform = strings.TrimSpace(o.Platform)
	if o.Platform == "" {
		o.Platform = runtime.GOOS + "-" + runtime.GOARCH
	}
	o.Ticket = strings.TrimSpace(o.Ticket)
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return o
}

func (o Options) validate() error {
	if o.Ticket == "" {
		return errors.New("missing bind ticket")
	}
	if o.ExternalSubjectID == "" {
		return errors.New("missing external subject id")
	}
	u, err := url.Parse(o.ServerURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("invalid server URL")
	}
	return nil
}

func joinURL(base string, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
