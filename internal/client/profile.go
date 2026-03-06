package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ProfileClient — HTTP-клиент для внутреннего API ProfileService.
type ProfileClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewProfileClient(baseURL string) *ProfileClient {
	return &ProfileClient{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// CreateProfile создаёт пустой профиль в ProfileService для указанного userID.
func (c *ProfileClient) CreateProfile(ctx context.Context, userID string) error {
	body, _ := json.Marshal(map[string]string{"user_id": userID})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/internal/profiles", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("profile service unavailable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("profile service returned %d", resp.StatusCode)
	}
	return nil
}
