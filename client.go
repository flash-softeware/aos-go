// Package aos is the Go SDK of the AOS identity engine, for an
// application's backend: it verifies the short-lived session token
// locally, answers permission questions, and manages users, roles,
// organizations and keys.
//
//	client, _ := aos.New(aos.Config{
//		URL:            os.Getenv("AOS_URL"),
//		PublishableKey: os.Getenv("AOS_PUBLISHABLE_KEY"),
//		SecretKey:      os.Getenv("AOS_SECRET_KEY"),
//	})
//	mux.Handle("/invoices", client.Middleware(client.RequirePermission("invoice.read", aos.Root)(handler)))
package aos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config says where the engine is and which tenant this application is.
type Config struct {
	// URL is the engine's address, such as https://auth.example.com or
	// http://localhost:8080.
	URL string
	// PublishableKey names the tenant. It is used to fetch the public keys
	// that verify session tokens.
	PublishableKey string
	// SecretKey lets this backend call the management API. Keep it out of
	// browsers and logs.
	SecretKey string
	// HTTPClient is optional.
	HTTPClient *http.Client
	// KeysTTL is how long fetched public keys are trusted before a refresh.
	// Zero means five minutes.
	KeysTTL time.Duration
}

// Client talks to one tenant of the engine.
type Client struct {
	cfg  Config
	base string
	http *http.Client
	mu        sync.Mutex
	keys      map[string]keyEntry
	keysAt    time.Time
	lastFetch time.Time
	now       func() time.Time
}

// New makes a client.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("aos: Config.URL must be an address such as https://auth.example.com")
	}
	if cfg.SecretKey != "" && !strings.HasPrefix(cfg.SecretKey, "sk_") {
		return nil, errors.New("aos: Config.SecretKey does not look like a secret key (sk_...)")
	}
	if cfg.PublishableKey != "" && !strings.HasPrefix(cfg.PublishableKey, "pk_") {
		return nil, errors.New("aos: Config.PublishableKey does not look like a publishable key (pk_...)")
	}
	if cfg.KeysTTL == 0 {
		cfg.KeysTTL = 5 * time.Minute
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{cfg: cfg, base: strings.TrimRight(cfg.URL, "/"), http: hc, now: time.Now}, nil
}

// APIError is an error answer from the engine.
type APIError struct {
	Status  int
	Type    string
	Code    string
	Message string
	Details map[string]string
}

func (e *APIError) Error() string {
	if len(e.Details) > 0 {
		return fmt.Sprintf("aos: %s (%s): %v", e.Message, e.Code, e.Details)
	}
	return fmt.Sprintf("aos: %s (%s)", e.Message, e.Code)
}

// IsCode reports whether err is an APIError with this code, such as
// "not_found" or "invalid_credentials".
func IsCode(err error, code string) bool {
	var e *APIError
	return errors.As(err, &e) && e.Code == code
}

type envelope struct {
	Status  int             `json:"status"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
	Error   *struct {
		Type    string            `json:"type"`
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Details map[string]string `json:"details"`
	} `json:"error"`
}

// door says which key a call sends.
type door int

const (
	backend door = iota
	frontend
)

// do sends one request and decodes the "data" of the answer into out.
func (c *Client) do(ctx context.Context, d door, method, path string, body, out any, extra ...string) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("aos: encode request: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "aos-go/"+Version)
	switch d {
	case backend:
		if c.cfg.SecretKey == "" {
			return errors.New("aos: this call needs Config.SecretKey")
		}
		req.Header.Set("Authorization", "Bearer "+c.cfg.SecretKey)
	case frontend:
		if c.cfg.PublishableKey == "" {
			return errors.New("aos: this call needs Config.PublishableKey")
		}
		req.Header.Set("X-AOS-Publishable-Key", c.cfg.PublishableKey)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		req.Header.Set(extra[i], extra[i+1])
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("aos: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return fmt.Errorf("aos: read answer: %w", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return &APIError{Status: resp.StatusCode, Code: "bad_answer", Message: fmt.Sprintf("the engine answered %d with something that is not JSON", resp.StatusCode)}
	}
	if resp.StatusCode >= 400 || env.Error != nil {
		e := &APIError{Status: resp.StatusCode}
		if env.Error != nil {
			e.Type, e.Code, e.Message, e.Details = env.Error.Type, env.Error.Code, env.Error.Message, env.Error.Details
		}
		return e
	}
	if out != nil && len(env.Data) > 0 && string(env.Data) != "null" {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("aos: decode answer: %w", err)
		}
	}
	return nil
}

// Version is the SDK version.
const Version = "0.4.0"
