package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendGuestWebhook(t *testing.T) {
	var receivedPayload GuestWebhookPayload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got %s", r.Header.Get("Content-Type"))
		}
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	payload := GuestWebhookPayload{
		Event:     "quota.warning",
		Timestamp: time.Now().Unix(),
		Guest: GuestInfo{
			Alias:          "alice",
			UsedBytes:      8 * 1024 * 1024 * 1024,
			UsedGB:         8.0,
			QuotaGB:        10.0,
			Percent:        80.0,
			ResetDay:       15,
			DaysUntilReset: 12,
			Status:         "enabled",
		},
		Message: "Guest [alice] reached 80.0% of quota.",
	}

	if err := SendGuestWebhook(ts.URL, payload); err != nil {
		t.Fatalf("SendGuestWebhook failed: %v", err)
	}

	if receivedPayload.Event != "quota.warning" {
		t.Fatalf("expected event 'quota.warning', got %q", receivedPayload.Event)
	}
	if receivedPayload.Guest.Alias != "alice" {
		t.Fatalf("expected guest 'alice', got %q", receivedPayload.Guest.Alias)
	}
}

func TestSendGuestWebhookEmptyURL(t *testing.T) {
	if err := SendGuestWebhook("", GuestWebhookPayload{}); err != nil {
		t.Fatalf("expected nil error for empty URL, got %v", err)
	}
}

func TestSendGuestWebhookErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	err := SendGuestWebhook(ts.URL, GuestWebhookPayload{})
	if err == nil {
		t.Fatalf("expected error for 500 response, got nil")
	}
}

func TestSendGuestWebhookNtfy(t *testing.T) {
	var receivedTitle, receivedPriority, receivedTags, receivedBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTitle = r.Header.Get("Title")
		receivedPriority = r.Header.Get("Priority")
		receivedTags = r.Header.Get("Tags")
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	payload := GuestWebhookPayload{
		Event:   "quota.trigger",
		Message: "Guest [bob] remaining quota is below 80p.",
	}

	ntfyURL := ts.URL + "/ntfy"
	if err := SendGuestWebhook(ntfyURL, payload); err != nil {
		t.Fatalf("SendGuestWebhook failed: %v", err)
	}

	if receivedTitle != "xray-proxya: quota.trigger" {
		t.Fatalf("expected Title 'xray-proxya: quota.trigger', got %q", receivedTitle)
	}
	if receivedPriority != "high" {
		t.Fatalf("expected Priority 'high', got %q", receivedPriority)
	}
	if receivedTags != "chart_with_upwards_trend" {
		t.Fatalf("expected Tags 'chart_with_upwards_trend', got %q", receivedTags)
	}
	if receivedBody != "Guest [bob] remaining quota is below 80p." {
		t.Fatalf("expected body %q, got %q", payload.Message, receivedBody)
	}
}
