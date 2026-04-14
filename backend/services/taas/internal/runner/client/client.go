// Package client provides an HTTP client that calls the Oktopus controller
// REST API on behalf of the TaaS test runner.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ControllerClient sends USP messages to a target device via the controller's
// REST API (/api/device/{sn}/{mtp}/<operation>).
type ControllerClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// New creates a new ControllerClient.
func New(baseURL, token string) *ControllerClient {
	return &ControllerClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// USPResponse is a generic envelope for any USP response JSON returned by the
// controller.  The caller is responsible for unmarshalling RawBody into the
// specific response type it expects.
type USPResponse struct {
	StatusCode int
	RawBody    json.RawMessage
}

// Get sends a USP Get message.
// body must serialise to {"param_paths": [...], "max_depth": 0}.
func (c *ControllerClient) Get(ctx context.Context, deviceID, mtp string, body any) (*USPResponse, error) {
	return c.sendUSP(ctx, deviceID, mtp, "get", body)
}

// Add sends a USP Add message.
func (c *ControllerClient) Add(ctx context.Context, deviceID, mtp string, body any) (*USPResponse, error) {
	return c.sendUSP(ctx, deviceID, mtp, "add", body)
}

// Set sends a USP Set message.
func (c *ControllerClient) Set(ctx context.Context, deviceID, mtp string, body any) (*USPResponse, error) {
	return c.sendUSP(ctx, deviceID, mtp, "set", body)
}

// Delete sends a USP Delete message.
func (c *ControllerClient) Delete(ctx context.Context, deviceID, mtp string, body any) (*USPResponse, error) {
	return c.sendUSP(ctx, deviceID, mtp, "del", body)
}

// Operate sends a USP Operate message.
func (c *ControllerClient) Operate(ctx context.Context, deviceID, mtp string, body any) (*USPResponse, error) {
	return c.sendUSP(ctx, deviceID, mtp, "operate", body)
}

// GetInstances sends a USP GetInstances message.
func (c *ControllerClient) GetInstances(ctx context.Context, deviceID, mtp string, body any) (*USPResponse, error) {
	return c.sendUSP(ctx, deviceID, mtp, "instances", body)
}

// GetSupportedDM sends a USP GetSupportedDM message.
func (c *ControllerClient) GetSupportedDM(ctx context.Context, deviceID, mtp string, body any) (*USPResponse, error) {
	return c.sendUSP(ctx, deviceID, mtp, "parameters", body)
}

// Notify sends a USP Notify message.
func (c *ControllerClient) Notify(ctx context.Context, deviceID, mtp string, body any) (*USPResponse, error) {
	return c.sendUSP(ctx, deviceID, mtp, "notify", body)
}

// Generic sends a raw USP message (protojson encoded usp_msg.Msg).
func (c *ControllerClient) Generic(ctx context.Context, deviceID, mtp string, body any) (*USPResponse, error) {
	return c.sendUSP(ctx, deviceID, mtp, "generic", body)
}

// GetDevices lists connected devices (GET /api/device).
func (c *ControllerClient) GetDevices(ctx context.Context) (*USPResponse, error) {
	return c.doRequest(ctx, http.MethodGet, "/api/device", nil)
}

func (c *ControllerClient) sendUSP(ctx context.Context, deviceID, mtp, op string, body any) (*USPResponse, error) {
	path := fmt.Sprintf("/api/device/%s/%s/%s", deviceID, mtp, op)
	return c.doRequest(ctx, http.MethodPut, path, body)
}

func (c *ControllerClient) doRequest(ctx context.Context, method, path string, body any) (*USPResponse, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	return &USPResponse{StatusCode: resp.StatusCode, RawBody: json.RawMessage(raw)}, nil
}

// ---------------------------------------------------------------------------
// Convenience helpers for decoding common response shapes
// ---------------------------------------------------------------------------

// IsUSPError returns true and the embedded error code when the response body
// represents a top-level USP Error message ({"err_code": N, "err_msg": "..."}).
func IsUSPError(raw json.RawMessage) (bool, uint32, string) {
	var e struct {
		ErrCode uint32 `json:"err_code"`
		ErrMsg  string `json:"err_msg"`
	}
	if err := json.Unmarshal(raw, &e); err == nil && e.ErrCode != 0 {
		return true, e.ErrCode, e.ErrMsg
	}
	return false, 0, ""
}
