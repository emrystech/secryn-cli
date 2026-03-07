package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const defaultUserAgent = "secryn-cli"

// APIError captures an HTTP error response from the API.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("api request failed with status %d", e.StatusCode)
	}
	return fmt.Sprintf("api request failed with status %d: %s", e.StatusCode, e.Message)
}

// Client performs authenticated calls to Secryn REST endpoints.
type Client struct {
	baseURL    *url.URL
	accessKey  string
	httpClient *http.Client
	userAgent  string
}

func New(baseURL, accessKey string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("base url must include scheme and host")
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	return &Client{
		baseURL:    parsed,
		accessKey:  strings.TrimSpace(accessKey),
		httpClient: httpClient,
		userAgent:  defaultUserAgent,
	}, nil
}

func (c *Client) ListSecrets(ctx context.Context, vaultID string) ([]Secret, error) {
	payload, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/vaults/%s", url.PathEscape(vaultID)), nil)
	if err != nil {
		return nil, err
	}
	items, err := decodeList[Secret](payload)
	if err != nil {
		return nil, fmt.Errorf("decode secrets list: %w", err)
	}
	return items, nil
}

func (c *Client) GetSecret(ctx context.Context, vaultID, name string) (Secret, error) {
	payload, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/vaults/%s/secrets/%s", url.PathEscape(vaultID), url.PathEscape(name)), nil)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			secrets, listErr := c.ListSecrets(ctx, vaultID)
			if listErr != nil {
				return Secret{}, listErr
			}
			for _, secret := range secrets {
				if secret.Name == name {
					return secret, nil
				}
			}
		}
		return Secret{}, err
	}
	item, err := decodeOne[Secret](payload)
	if err != nil {
		return Secret{}, fmt.Errorf("decode secret: %w", err)
	}
	return item, nil
}

func (c *Client) ListKeys(ctx context.Context, vaultID string) ([]Key, error) {
	payload, err := c.doWithAccessKeyFallback(ctx, http.MethodGet, fmt.Sprintf("/v1/vaults/%s/keys", url.PathEscape(vaultID)), nil)
	if err != nil {
		return nil, err
	}
	items, err := decodeList[Key](payload)
	if err != nil {
		return nil, fmt.Errorf("decode keys list: %w", err)
	}
	return items, nil
}

func (c *Client) DownloadKey(ctx context.Context, vaultID, keyID string) ([]byte, error) {
	primaryEndpoint := fmt.Sprintf("/v1/vaults/%s/keys/%s/download", url.PathEscape(vaultID), url.PathEscape(keyID))
	payload, err := c.doWithAccessKeyFallback(ctx, http.MethodGet, primaryEndpoint, nil)
	if err == nil {
		return payload, nil
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) || (apiErr.StatusCode != http.StatusNotFound && apiErr.StatusCode != http.StatusGone) {
		return nil, err
	}

	fallbackEndpoint := fmt.Sprintf("/v1/vaults/%s?resource=%s", url.PathEscape(vaultID), url.QueryEscape(keyID))
	return c.doWithAccessKeyFallback(ctx, http.MethodGet, fallbackEndpoint, nil)
}

func (c *Client) ListCertificates(ctx context.Context, vaultID string) ([]Certificate, error) {
	payload, err := c.doWithAccessKeyFallback(ctx, http.MethodGet, fmt.Sprintf("/v1/vaults/%s/certificates", url.PathEscape(vaultID)), nil)
	if err != nil {
		return nil, err
	}
	items, err := decodeList[Certificate](payload)
	if err != nil {
		return nil, fmt.Errorf("decode certificate list: %w", err)
	}
	return items, nil
}

func (c *Client) DownloadCertificate(ctx context.Context, vaultID, certID string) ([]byte, error) {
	primaryEndpoint := fmt.Sprintf("/v1/vaults/%s/certificates/%s/download", url.PathEscape(vaultID), url.PathEscape(certID))
	payload, err := c.doWithAccessKeyFallback(ctx, http.MethodGet, primaryEndpoint, nil)
	if err == nil {
		return payload, nil
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) || (apiErr.StatusCode != http.StatusNotFound && apiErr.StatusCode != http.StatusGone) {
		return nil, err
	}

	fallbackEndpoint := fmt.Sprintf("/v1/vaults/%s?resource=%s", url.PathEscape(vaultID), url.QueryEscape(certID))
	return c.doWithAccessKeyFallback(ctx, http.MethodGet, fallbackEndpoint, nil)
}

func (c *Client) AuthTest(ctx context.Context, vaultID string) error {
	_, err := c.ListSecrets(ctx, vaultID)
	return err
}

func AsAPIError(err error, target *APIError) bool {
	matched, ok := err.(*APIError)
	if !ok {
		return false
	}
	*target = *matched
	return true
}

func (c *Client) do(ctx context.Context, method, endpoint string, body []byte) ([]byte, error) {
	return c.doWithQuery(ctx, method, endpoint, nil, body)
}

func (c *Client) doWithAccessKeyFallback(ctx context.Context, method, endpoint string, body []byte) ([]byte, error) {
	respBody, err := c.do(ctx, method, endpoint, body)
	if err == nil || !c.shouldRetryWithQueryAccessKey(err) {
		return respBody, err
	}

	return c.doWithQuery(ctx, method, endpoint, url.Values{"access_key": []string{c.accessKey}}, body)
}

func (c *Client) shouldRetryWithQueryAccessKey(err error) bool {
	if strings.TrimSpace(c.accessKey) == "" {
		return false
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden
}

func (c *Client) doWithQuery(ctx context.Context, method, endpoint string, query url.Values, body []byte) ([]byte, error) {
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint: %w", err)
	}

	fullURL := *c.baseURL
	fullURL.Path = path.Join(c.baseURL.Path, parsedEndpoint.Path)

	combinedQuery := fullURL.Query()
	for key, values := range parsedEndpoint.Query() {
		for _, value := range values {
			combinedQuery.Add(key, value)
		}
	}
	for key, values := range query {
		combinedQuery.Del(key)
		for _, value := range values {
			combinedQuery.Add(key, value)
		}
	}
	fullURL.RawQuery = combinedQuery.Encode()

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if c.accessKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessKey)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, parseAPIError(resp.StatusCode, respBody)
	}

	return respBody, nil
}

func parseAPIError(statusCode int, respBody []byte) error {
	message := strings.TrimSpace(string(respBody))
	if json.Valid(respBody) {
		var container struct {
			Error   string `json:"error"`
			Message string `json:"message"`
			Detail  string `json:"detail"`
		}
		if err := json.Unmarshal(respBody, &container); err == nil {
			switch {
			case container.Message != "":
				message = container.Message
			case container.Error != "":
				message = container.Error
			case container.Detail != "":
				message = container.Detail
			}
		}
	}
	if message == "" {
		message = http.StatusText(statusCode)
	}
	return &APIError{StatusCode: statusCode, Message: message}
}

func decodeList[T any](payload []byte) ([]T, error) {
	var direct []T
	if err := json.Unmarshal(payload, &direct); err == nil {
		return direct, nil
	}

	var wrapped struct {
		Items   []T `json:"items"`
		Data    []T `json:"data"`
		Secrets []T `json:"secrets"`
	}
	if err := json.Unmarshal(payload, &wrapped); err != nil {
		return nil, err
	}
	if wrapped.Items != nil {
		return wrapped.Items, nil
	}
	if wrapped.Data != nil {
		return wrapped.Data, nil
	}
	if wrapped.Secrets != nil {
		return wrapped.Secrets, nil
	}
	return nil, fmt.Errorf("unexpected payload shape")
}

func decodeOne[T any](payload []byte) (T, error) {
	var zero T

	var wrapped struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(payload, &wrapped); err == nil && len(wrapped.Data) > 0 {
		var item T
		if err := json.Unmarshal(wrapped.Data, &item); err != nil {
			return zero, err
		}
		return item, nil
	}

	var direct T
	if err := json.Unmarshal(payload, &direct); err == nil {
		return direct, nil
	}
	return zero, fmt.Errorf("unexpected payload shape")
}
