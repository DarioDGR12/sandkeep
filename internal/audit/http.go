package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// HTTPSink POSTs each event as JSON to URL. Optional Bearer token.
type HTTPSink struct {
	URL    string
	Token  string
	Client *http.Client
}

// Record implements Logger.
func (h HTTPSink) Record(event Event) error {
	if h.URL == "" {
		return fmt.Errorf("audit http: empty URL")
	}
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequest(http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.Token != "" {
		req.Header.Set("Authorization", "Bearer "+h.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("audit http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("audit http: status %d", resp.StatusCode)
	}
	return nil
}
