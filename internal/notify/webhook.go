package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type GuestInfo struct {
	Alias          string  `json:"alias"`
	UsedBytes      int64   `json:"used_bytes"`
	UsedGB         float64 `json:"used_gb"`
	QuotaGB        float64 `json:"quota_gb"`
	Percent        float64 `json:"percent"`
	ResetDay       int     `json:"reset_day"`
	DaysUntilReset int     `json:"days_until_reset"`
	Status         string  `json:"status"`
}

type GuestWebhookPayload struct {
	Event     string    `json:"event"`
	Timestamp int64     `json:"timestamp"`
	Guest     GuestInfo `json:"guest"`
	Message   string    `json:"message"`
}

var (
	HTTPClient = &http.Client{
		Timeout: 10 * time.Second,
	}
	WebhookSender = SendGuestWebhook
	wg            sync.WaitGroup
)

func SendGuestWebhook(webhookURL string, payload GuestWebhookPayload) error {
	if webhookURL == "" {
		return nil
	}

	var req *http.Request
	var err error

	if strings.Contains(webhookURL, "ntfy.sh") || strings.Contains(webhookURL, "/ntfy") {
		req, err = http.NewRequestWithContext(context.Background(), http.MethodPost, webhookURL, strings.NewReader(payload.Message))
		if err != nil {
			return fmt.Errorf("create ntfy request: %w", err)
		}
		req.Header.Set("Title", fmt.Sprintf("xray-proxya: %s", payload.Event))
		switch payload.Event {
		case "quota.exceeded":
			req.Header.Set("Priority", "urgent")
			req.Header.Set("Tags", "warning,rotating_light")
		case "quota.trigger", "quota.warning":
			req.Header.Set("Priority", "high")
			req.Header.Set("Tags", "chart_with_upwards_trend")
		case "quota.reset":
			req.Header.Set("Priority", "default")
			req.Header.Set("Tags", "recycle,white_check_mark")
		default:
			req.Header.Set("Priority", "default")
		}
	} else {
		data, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			return fmt.Errorf("marshal webhook payload: %w", marshalErr)
		}
		req, err = http.NewRequestWithContext(context.Background(), http.MethodPost, webhookURL, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("create webhook request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
	}

	req.Header.Set("User-Agent", "xray-proxya")

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute webhook request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook responded with status: %d", resp.StatusCode)
	}
	return nil
}

func SendGuestWebhookAsync(webhookURL string, payload GuestWebhookPayload) {
	if webhookURL == "" {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := WebhookSender(webhookURL, payload); err != nil {
			log.Printf("⚠️ Webhook notification to %s failed: %v\n", webhookURL, err)
		}
	}()
}

// Wait blocks until all pending async webhook dispatches finish or timeout.
func Wait() {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}
