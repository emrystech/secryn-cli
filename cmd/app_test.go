package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestExecuteArgsJSONValidationError(t *testing.T) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.envLookup = func(string) string { return "" }

	if got := app.ExecuteArgs([]string{"secret", "get", "name", "--json", "--config", filepath.Join(t.TempDir(), "config.yaml")}); got != exitUsage {
		t.Fatalf("exit code = %d, want %d", got, exitUsage)
	}
	assertJSONError(t, stderr.Bytes(), "validation_error", 0)
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestUpdateSkipsInvalidVaultConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(": invalid yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.envLookup = func(string) string { return "" }

	if got := app.ExecuteArgs([]string{"update", "--check", "--version", "invalid", "--json", "--config", configPath}); got != exitUsage {
		t.Fatalf("exit code = %d, want %d", got, exitUsage)
	}
	assertJSONError(t, stderr.Bytes(), "validation_error", 0)
}

func TestExecuteArgsJSONNotFoundError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Vault not found"}`))
	}))
	defer server.Close()

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("base_url: "+server.URL+"\nvault_id: vault\naccess_key: token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.envLookup = func(string) string { return "" }

	if got := app.ExecuteArgs([]string{"secret", "list", "--json", "--config", configPath}); got != exitNotFound {
		t.Fatalf("exit code = %d, want %d", got, exitNotFound)
	}
	assertJSONError(t, stderr.Bytes(), "not_found", http.StatusNotFound)
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func assertJSONError(t *testing.T, payload []byte, wantCode string, wantStatus int) {
	t.Helper()
	var response struct {
		OK    bool `json:"ok"`
		Error struct {
			Code       string `json:"code"`
			Message    string `json:"message"`
			HTTPStatus int    `json:"http_status"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatalf("stderr is not JSON: %v; payload=%q", err, payload)
	}
	if response.OK || response.Error.Code != wantCode || response.Error.HTTPStatus != wantStatus || response.Error.Message == "" {
		t.Fatalf("JSON error = %+v, want ok=false code=%q http_status=%d", response, wantCode, wantStatus)
	}
}
