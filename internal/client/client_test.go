package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListSecretsWrappedInVaultObject(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/vaults/vault-1" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"unexpected path"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{
			"id":"8d242894-044e-461e-a0cc-d5f63841b7d7",
			"name":"stripe-ca",
			"secrets":[
				{
					"id":"ce144f6a-a662-4cd2-9325-cb93698b9ff1",
					"name":"secryn-payout-link-1",
					"value":"https://buy.stripe.com/eVq8wH64Re5Camo5iV8AE00",
					"content_type":"text/plain",
					"tags":[]
				}
			]
		}`)
	}))
	defer ts.Close()

	cli, err := New(ts.URL, "token", ts.Client())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	secrets, err := cli.ListSecrets(context.Background(), "vault-1")
	if err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("len(secrets) = %d, want 1", len(secrets))
	}
	if secrets[0].Name != "secryn-payout-link-1" {
		t.Fatalf("secrets[0].Name = %q, want secryn-payout-link-1", secrets[0].Name)
	}
	if secrets[0].Value != "https://buy.stripe.com/eVq8wH64Re5Camo5iV8AE00" {
		t.Fatalf("secrets[0].Value = %q, unexpected", secrets[0].Value)
	}
}

func TestGetSecretFallsBackToVaultPayloadOn404(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vaults/vault-1/secrets/DB_PASSWORD":
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"not found"}`)
		case "/v1/vaults/vault-1":
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{
				"id":"vault-id",
				"name":"vault",
				"secrets":[{"name":"DB_PASSWORD","value":"super-secret"}]
			}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"unexpected path"}`)
		}
	}))
	defer ts.Close()

	cli, err := New(ts.URL, "token", ts.Client())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	secret, err := cli.GetSecret(context.Background(), "vault-1", "DB_PASSWORD")
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if secret.Name != "DB_PASSWORD" {
		t.Fatalf("secret.Name = %q, want DB_PASSWORD", secret.Name)
	}
	if secret.Value != "super-secret" {
		t.Fatalf("secret.Value = %q, want super-secret", secret.Value)
	}
}

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
				if r.URL.Path != "/v1/vaults/vault-1" {
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

func TestListKeysRetriesWithAccessKeyQueryOnUnauthorized(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/vaults/vault-1/keys" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"unexpected path"}`)
			return
		}

		if r.URL.Query().Get("access_key") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"message":"missing query token"}`)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `[{"id":"7283e707-ba2d-4d18-958c-3a2d60faf558","name":"private-key","key_type":"RSA","key_size":2048}]`)
	}))
	defer ts.Close()

	cli, err := New(ts.URL, "access-token", ts.Client())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	keys, err := cli.ListKeys(context.Background(), "vault-1")
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(keys))
	}
	if keys[0].Name != "private-key" {
		t.Fatalf("keys[0].Name = %q, want private-key", keys[0].Name)
	}
	if keys[0].KeyType != "RSA" {
		t.Fatalf("keys[0].KeyType = %q, want RSA", keys[0].KeyType)
	}
	if keys[0].KeySize != 2048 {
		t.Fatalf("keys[0].KeySize = %d, want 2048", keys[0].KeySize)
	}
}

func TestDownloadKeyFallsBackToVaultResourceEndpoint(t *testing.T) {
	t.Parallel()

	const keyID = "7283e707-ba2d-4d18-958c-3a2d60faf558"
	const keyBody = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/vaults/vault-1/keys/"+keyID+"/download":
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"not found"}`)
		case r.URL.Path == "/v1/vaults/vault-1" && r.URL.Query().Get("resource") == keyID:
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, keyBody)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"unexpected path"}`)
		}
	}))
	defer ts.Close()

	cli, err := New(ts.URL, "access-token", ts.Client())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, err := cli.DownloadKey(context.Background(), "vault-1", keyID)
	if err != nil {
		t.Fatalf("DownloadKey() error = %v", err)
	}
	if string(got) != keyBody {
		t.Fatalf("DownloadKey() body mismatch\nwant: %q\ngot:  %q", keyBody, string(got))
	}
}

func TestDownloadCertificateFallsBackToVaultResourceEndpoint(t *testing.T) {
	t.Parallel()

	const certID = "5dd05f89-acf6-4f40-93d4-bde04303d7ad"
	const certBody = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/vaults/vault-1/certificates/"+certID+"/download":
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"not found"}`)
		case r.URL.Path == "/v1/vaults/vault-1" && r.URL.Query().Get("resource") == certID:
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, certBody)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"unexpected path"}`)
		}
	}))
	defer ts.Close()

	cli, err := New(ts.URL, "access-token", ts.Client())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, err := cli.DownloadCertificate(context.Background(), "vault-1", certID)
	if err != nil {
		t.Fatalf("DownloadCertificate() error = %v", err)
	}
	if string(got) != certBody {
		t.Fatalf("DownloadCertificate() body mismatch\nwant: %q\ngot:  %q", certBody, string(got))
	}
}

func TestListCertificatesParsesArrayPayload(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/vaults/vault-1/certificates" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"unexpected path"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `[{"id":"811510c1-1113-4ae1-b9ee-d77379a5a1d8","name":"Server Side Up","type":"uploaded","expires_at":"2027-02-11T22:26:00.000000Z"}]`)
	}))
	defer ts.Close()

	cli, err := New(ts.URL, "access-token", ts.Client())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	certs, err := cli.ListCertificates(context.Background(), "vault-1")
	if err != nil {
		t.Fatalf("ListCertificates() error = %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1", len(certs))
	}
	if certs[0].Type != "uploaded" {
		t.Fatalf("certs[0].Type = %q, want uploaded", certs[0].Type)
	}
	if certs[0].ExpiresAt != "2027-02-11T22:26:00.000000Z" {
		t.Fatalf("certs[0].ExpiresAt = %q, unexpected", certs[0].ExpiresAt)
	}
}
