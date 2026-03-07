package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIErrorHandling(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		body       string
		wantMsg    string
	}{
		{name: "unauthorized", statusCode: http.StatusUnauthorized, body: `{"message":"bad token"}`, wantMsg: "bad token"},
		{name: "forbidden", statusCode: http.StatusForbidden, body: `{"error":"denied"}`, wantMsg: "denied"},
		{name: "not-found", statusCode: http.StatusNotFound, body: `{"detail":"missing"}`, wantMsg: "missing"},
		{name: "gone", statusCode: http.StatusGone, body: "", wantMsg: "Gone"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/vaults/vault-1/secrets" {
					w.WriteHeader(http.StatusNotFound)
					_, _ = fmt.Fprint(w, `{"message":"unexpected path"}`)
					return
				}
				w.WriteHeader(tt.statusCode)
				_, _ = fmt.Fprint(w, tt.body)
			}))
			defer ts.Close()

			cli, err := New(ts.URL, "token", ts.Client())
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			_, err = cli.ListSecrets(context.Background(), "vault-1")
			if err == nil {
				t.Fatalf("ListSecrets() expected error")
			}

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("ListSecrets() error type = %T, want *APIError", err)
			}
			if apiErr.StatusCode != tt.statusCode {
				t.Fatalf("status = %d, want %d", apiErr.StatusCode, tt.statusCode)
			}
			if apiErr.Message != tt.wantMsg {
				t.Fatalf("message = %q, want %q", apiErr.Message, tt.wantMsg)
			}
		})
	}
}
