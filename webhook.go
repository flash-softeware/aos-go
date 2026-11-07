package aos

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Event is one webhook delivery.
type Event struct {
	ID        string          `json:"id"`
	Type      string          `json:"event"`
	CreatedAt time.Time       `json:"created_at"`
	Data      json.RawMessage `json:"data"`
}

// ErrBadSignature is returned for a delivery that was not signed with the
// endpoint's secret, or is too old.
var ErrBadSignature = errors.New("aos: webhook signature does not match")

// VerifyWebhook checks the X-AOS-Signature header ("t=<unix>,v1=<hex>")
// of a delivery and returns the event. tolerance bounds how old a
// delivery may be; zero means five minutes.
func VerifyWebhook(secret string, header string, body []byte, tolerance time.Duration) (*Event, error) {
	return verifyWebhookAt(secret, header, body, tolerance, time.Now())
}

func verifyWebhookAt(secret, header string, body []byte, tolerance time.Duration, now time.Time) (*Event, error) {
	if tolerance == 0 {
		tolerance = 5 * time.Minute
	}
	var ts string
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sigs = append(sigs, v)
		}
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(sigs) == 0 {
		return nil, ErrBadSignature
	}
	if d := now.Sub(time.Unix(unix, 0)); d > tolerance || d < -tolerance {
		return nil, ErrBadSignature
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	want := mac.Sum(nil)
	ok := false
	for _, s := range sigs {
		got, err := hex.DecodeString(s)
		if err == nil && hmac.Equal(got, want) {
			ok = true
		}
	}
	if !ok {
		return nil, ErrBadSignature
	}
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

// WebhookHandler verifies each delivery and passes the event to handle.
// A bad signature gets 400; an error from handle gets 500, so the engine
// retries.
func WebhookHandler(secret string, handle func(*http.Request, *Event) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		ev, err := VerifyWebhook(secret, r.Header.Get("X-AOS-Signature"), body, 0)
		if err != nil {
			http.Error(w, "bad signature", http.StatusBadRequest)
			return
		}
		if err := handle(r, ev); err != nil {
			http.Error(w, "not handled", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
