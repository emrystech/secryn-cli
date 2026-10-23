package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecretListUpdatedAt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		want    string
		missing string
	}{
		{
			name: "uses updated_at when the api sends it",
			body: `{
				"id":"vault",
				"name":"vault",
				"secrets":[{"name":"TEST_VAR_A","value":"fixture-list","content_type":"text/plain","updated_at":"2026-03-07T15:04:05Z"}]
			}`,
			want:    "2026-03-07T15:04:05Z",
			missing: "fixture-list",
		},
		{
			name: "empty when the api omits a timestamp",
			body: `{
				"id":"vault",
				"name":"vault",
				"secrets":[{"id":"item-1","name":"TEST_VAR_A","value":"fixture-list","content_type":"text/plain","tags":[]}]
			}`,
			missing: "fixture-list",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/vaults/vault" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.body))
			}))
			t.Cleanup(server.Close)

			stdout, stderr := &strings.Builder{}, &strings.Builder{}
			app := NewApp(stdout, stderr)
			app.envLookup = func(string) string { return "" }
			cfg := writeConfigFile(t, configBody(server.URL, "vault", valAuth))
			if code := app.ExecuteArgs([]string{"secret", "list", "--config", cfg}); code != 0 {
				t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "UPDATED_AT") || !strings.Contains(stdout.String(), "TEST_VAR_A") {
				t.Fatalf("stdout = %q", stdout.String())
			}
			if tt.want != "" && !strings.Contains(stdout.String(), tt.want) {
				t.Fatalf("stdout = %q, want %s", stdout.String(), tt.want)
			}
			if tt.want == "" && strings.Contains(stdout.String(), "2026-") {
				t.Fatalf("invented a timestamp: %q", stdout.String())
			}
			if strings.Contains(stdout.String(), tt.missing) {
				t.Fatalf("secret value leaked into list output: %q", stdout.String())
			}
		})
	}
}
