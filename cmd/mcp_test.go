package cmd

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMCPServeUsesLocalE2EEAndKeepsStdoutProtocolPure(t *testing.T) {
	server, environment, legacyRequests := newCommandE2EEFixture(t)
	defer server.Close()
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"secryn_secret_get","arguments":{"name":"PIPELINE_TOKEN"}}}`,
	}, "\n") + "\n"
	reader, writer := io.Pipe()
	stdout, stderr := &commandNotifyingBuffer{frames: make(chan struct{}, 4)}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.stdin = reader
	app.httpClient = server.Client()
	app.envLookup = func(name string) string { return environment[name] }
	done := make(chan int, 1)
	go func() {
		done <- app.ExecuteArgs([]string{"mcp", "serve", "--config", filepath.Join(t.TempDir(), "missing.yaml")})
	}()
	if _, err := io.WriteString(writer, input); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		select {
		case <-stdout.frames:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for MCP output: %s", stdout.String())
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if code := <-done; code != exitOK {
		t.Fatalf("mcp serve exit code = %d, stderr = %s", code, stderr.String())
	}
	if legacyRequests.Load() != 0 || stderr.Len() != 0 {
		t.Fatalf("MCP used legacy API or emitted diagnostics: %s", stderr.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if !strings.HasPrefix(line, "{") || !strings.Contains(line, `"jsonrpc":"2.0"`) {
			t.Fatalf("stdout contained a non-protocol line: %q", line)
		}
	}
	if !strings.Contains(stdout.String(), "fixture-value") || strings.Contains(stdout.String(), environment["SECRYN_ACCESS_KEY"]) ||
		strings.Contains(stdout.String(), environment["SECRYN_RECIPIENT_PRIVATE_KEY"]) {
		t.Fatal("MCP result missing requested plaintext or exposed credentials")
	}
}

type commandNotifyingBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	frames chan struct{}
}

func (w *commandNotifyingBuffer) Write(payload []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buffer.Write(payload)
	w.mu.Unlock()
	if bytes.Contains(payload, []byte{'\n'}) {
		w.frames <- struct{}{}
	}
	return n, err
}

func (w *commandNotifyingBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}

func TestMCPServeRejectsLegacyModeBeforeReadingOrNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}` + "\n")
	app.httpClient = server.Client()
	app.envLookup = func(name string) string {
		values := map[string]string{"SECRYN_BASE_URL": server.URL, "SECRYN_VAULT_ID": "vault-uri", "SECRYN_ACCESS_KEY": "access-token"}
		return values[name]
	}
	if code := app.ExecuteArgs([]string{"mcp", "serve", "--config", filepath.Join(t.TempDir(), "missing.yaml")}); code != exitUsage {
		t.Fatalf("legacy MCP exit code = %d", code)
	}
	if stdout.Len() != 0 || requests.Load() != 0 || !strings.Contains(stderr.String(), "requires a complete E2EE identity") {
		t.Fatal("legacy MCP did not fail closed before transport/API use")
	}
}
