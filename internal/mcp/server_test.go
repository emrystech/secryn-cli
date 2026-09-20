package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/secryn/secryn-cli/internal/client"
	secretservice "github.com/secryn/secryn-cli/internal/secrets"
)

type fakeSecrets struct {
	list          func(context.Context, string) ([]client.Secret, error)
	get           func(context.Context, string, string) (client.Secret, error)
	listResources func(context.Context, string, string) ([]secretservice.DecryptedResource, error)
	getResource   func(context.Context, string, string, string) (secretservice.DecryptedResource, error)
}

func (f fakeSecrets) List(ctx context.Context, vault string) ([]client.Secret, error) {
	return f.list(ctx, vault)
}

func (f fakeSecrets) Get(ctx context.Context, vault, name string) (client.Secret, error) {
	return f.get(ctx, vault, name)
}

func (f fakeSecrets) ListResources(ctx context.Context, vault, resourceType string) ([]secretservice.DecryptedResource, error) {
	if f.listResources == nil {
		return nil, nil
	}
	return f.listResources(ctx, vault, resourceType)
}

func (f fakeSecrets) GetResourceByName(ctx context.Context, vault, resourceType, name string) (secretservice.DecryptedResource, error) {
	if f.getResource == nil {
		return secretservice.DecryptedResource{}, errors.New("not configured")
	}
	return f.getResource(ctx, vault, resourceType, name)
}

func TestServerHandshakeToolsAndStdoutPurity(t *testing.T) {
	provider := fakeSecrets{
		list: func(_ context.Context, vault string) ([]client.Secret, error) {
			if vault != "vault-uri" {
				t.Fatal("wrong vault URI")
			}
			return []client.Secret{{Name: "DB_PASSWORD", Value: "must-not-appear-in-list", UpdatedAt: "2026-01-01"}}, nil
		},
		get: func(_ context.Context, vault, name string) (client.Secret, error) {
			if vault != "vault-uri" || name != "DB_PASSWORD" {
				t.Fatal("wrong get arguments")
			}
			return client.Secret{Name: name, Value: "requested-plaintext", UpdatedAt: "2026-01-01"}, nil
		},
	}
	diagnostics := &bytes.Buffer{}
	server, err := New(provider, "vault-uri", "v1.2.3", diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"secryn_secret_list","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"secryn_secret_get","arguments":{"name":"DB_PASSWORD"}}}`,
	}, "\n") + "\n"
	stdout := serveUntilFrames(t, server, input, 4)
	frames := decodeFrames(t, stdout)
	if len(frames) != 4 {
		t.Fatalf("response frames = %d, output = %s", len(frames), stdout)
	}
	if diagnostics.Len() != 0 || strings.Contains(string(stdout), "must-not-appear-in-list") {
		t.Fatal("MCP output leaked an unrequested secret or emitted diagnostics on stdout")
	}
	if !strings.Contains(string(stdout), "requested-plaintext") {
		t.Fatal("requested secret was not returned in the tool result")
	}
	if strings.Contains(string(stdout), "MCP:") {
		t.Fatal("stdout contained a diagnostic frame")
	}
}

func TestServerProtocolErrorsAndRedactedToolFailure(t *testing.T) {
	const sensitive = "access-private-vek-dek-plaintext"
	provider := fakeSecrets{
		list: func(context.Context, string) ([]client.Secret, error) { return nil, errors.New(sensitive) },
		get: func(context.Context, string, string) (client.Secret, error) {
			return client.Secret{}, errors.New(sensitive)
		},
	}
	diagnostics := &bytes.Buffer{}
	server, err := New(provider, "vault-uri", "test", diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	input := "{bad json}\n" +
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"secryn_secret_get","arguments":{"name":"SAFE"}}}` + "\n"
	stdout := serveUntilFrames(t, server, input, 4)
	if strings.Contains(string(stdout)+diagnostics.String(), sensitive) {
		t.Fatal("MCP failure exposed sensitive error material")
	}
	if !strings.Contains(string(stdout), `"code":-32700`) || !strings.Contains(string(stdout), `"code":-32002`) ||
		!strings.Contains(string(stdout), `"isError":true`) {
		t.Fatalf("missing protocol/tool errors: %s", stdout)
	}
	if !strings.Contains(diagnostics.String(), "secryn_secret_get failed") {
		t.Fatal("safe tool diagnostic was not sent to stderr sink")
	}
}

func TestServerCancellationCancelsToolWithoutResponse(t *testing.T) {
	var cancelled atomic.Bool
	provider := fakeSecrets{
		list: func(context.Context, string) ([]client.Secret, error) { return nil, nil },
		get: func(ctx context.Context, _, _ string) (client.Secret, error) {
			<-ctx.Done()
			cancelled.Store(true)
			return client.Secret{}, ctx.Err()
		},
	}
	server, err := New(provider, "vault-uri", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":"call-1","method":"tools/call","params":{"name":"secryn_secret_get","arguments":{"name":"SAFE"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"call-1","reason":"test"}}`,
	}, "\n") + "\n"
	stdout := &bytes.Buffer{}
	if err := server.Serve(context.Background(), strings.NewReader(input), stdout); err != nil {
		t.Fatal(err)
	}
	if !cancelled.Load() || strings.Contains(stdout.String(), `"id":"call-1"`) {
		t.Fatalf("cancelled tool response/state invalid: %s", stdout.String())
	}
}

func TestServerRejectsOversizedInputFrame(t *testing.T) {
	provider := fakeSecrets{
		list: func(context.Context, string) ([]client.Secret, error) { return nil, nil },
		get:  func(context.Context, string, string) (client.Secret, error) { return client.Secret{}, nil },
	}
	server, err := New(provider, "vault-uri", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	stdout := &bytes.Buffer{}
	err = server.Serve(context.Background(), strings.NewReader(strings.Repeat("x", MaxInputFrame+1)+"\n"), stdout)
	if err == nil || !strings.Contains(stdout.String(), `"code":-32700`) {
		t.Fatalf("oversized frame result = %v, %s", err, stdout.String())
	}
}

func TestLegacyInitializeUnsupportedVersionUsesStructuredError(t *testing.T) {
	provider := fakeSecrets{
		list: func(context.Context, string) ([]client.Secret, error) { return nil, nil },
		get:  func(context.Context, string, string) (client.Secret, error) { return client.Secret{}, nil },
	}
	server, err := New(provider, "vault-uri", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	stdout := &bytes.Buffer{}
	if err := server.Serve(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}`+"\n"), stdout); err != nil {
		t.Fatal(err)
	}
	frame := decodeFrames(t, stdout.Bytes())[0]
	rpcErr := frame["error"].(map[string]any)
	data := rpcErr["data"].(map[string]any)
	versions := data["supportedVersions"].([]any)
	if rpcErr["code"] != float64(-32022) || len(versions) != len(legacyProtocolVersions) {
		t.Fatalf("unexpected unsupported legacy version response: %#v", rpcErr)
	}
}

func TestFinalEncodedFrameOverflowReturnsBoundedError(t *testing.T) {
	provider := fakeSecrets{
		list: func(context.Context, string) ([]client.Secret, error) { return nil, nil },
		get:  func(context.Context, string, string) (client.Secret, error) { return client.Secret{}, nil },
	}
	server, err := New(provider, "vault-uri", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	heavy := strings.Repeat("\"\\\n\t", 300_000)
	result, protocolErr := toolSuccess(client.Secret{Name: "SAFE", Value: heavy})
	if protocolErr != nil {
		t.Fatal(protocolErr)
	}
	stdout := &bytes.Buffer{}
	server.writeResult(stdout, json.RawMessage("7"), result, false)
	if stdout.Len() >= MaxOutputFrame {
		t.Fatalf("bounded fallback frame is too large: %d", stdout.Len())
	}
	frames := decodeFrames(t, stdout.Bytes())
	if len(frames) != 1 || frames[0]["result"] != nil || frames[0]["error"].(map[string]any)["code"] != float64(-32001) {
		t.Fatalf("overflow did not return a bounded JSON-RPC error: %s", stdout.String())
	}
}

func TestCleanEOFCancelsBlockedTool(t *testing.T) {
	cancelled := make(chan struct{})
	provider := fakeSecrets{
		list: func(context.Context, string) ([]client.Secret, error) { return nil, nil },
		get: func(ctx context.Context, _, _ string) (client.Secret, error) {
			<-ctx.Done()
			close(cancelled)
			return client.Secret{}, ctx.Err()
		},
	}
	server, err := New(provider, "vault-uri", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"secryn_secret_get","arguments":{"name":"SAFE"}}}`,
	}, "\n") + "\n"
	if err := server.Serve(context.Background(), strings.NewReader(input), io.Discard); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("clean EOF did not cancel the blocked provider")
	}
}

func TestInvalidNotificationsEmitNothingAndDoNotPinEra(t *testing.T) {
	provider := fakeSecrets{
		list: func(context.Context, string) ([]client.Secret, error) { return nil, nil },
		get:  func(context.Context, string, string) (client.Secret, error) { return client.Secret{}, nil },
	}
	t.Run("unknown era", func(t *testing.T) {
		server, _ := New(provider, "vault-uri", "test", nil)
		input := strings.Join([]string{
			`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`,
			`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}`,
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
		}, "\n") + "\n"
		stdout := &bytes.Buffer{}
		if err := server.Serve(context.Background(), strings.NewReader(input), stdout); err != nil {
			t.Fatal(err)
		}
		frames := decodeFrames(t, stdout.Bytes())
		if len(frames) != 1 || frames[0]["result"] == nil {
			t.Fatalf("notifications emitted output or pinned an era: %s", stdout.String())
		}
	})
	t.Run("cross era", func(t *testing.T) {
		server, _ := New(provider, "vault-uri", "test", nil)
		input := strings.Join([]string{
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
			`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
		}, "\n") + "\n"
		stdout := &bytes.Buffer{}
		if err := server.Serve(context.Background(), strings.NewReader(input), stdout); err != nil {
			t.Fatal(err)
		}
		if frames := decodeFrames(t, stdout.Bytes()); len(frames) != 1 {
			t.Fatalf("era-mismatch notification emitted a response: %s", stdout.String())
		}
	})
}

func TestServerModernDiscoveryAndDirectTools(t *testing.T) {
	provider := fakeSecrets{
		list: func(context.Context, string) ([]client.Secret, error) { return nil, nil },
		get:  func(context.Context, string, string) (client.Secret, error) { return client.Secret{}, nil },
	}
	server, err := New(provider, "vault-uri", "v2.0.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
	}, "\n") + "\n"
	stdout := serveUntilFrames(t, server, input, 2)
	frames := decodeFrames(t, stdout)
	if len(frames) != 2 {
		t.Fatalf("response frames = %d: %s", len(frames), stdout)
	}
	discover := frames[0]["result"].(map[string]any)
	versions := discover["supportedVersions"].([]any)
	if len(versions) != 1 || versions[0] != ModernProtocolVersion || discover["resultType"] != "complete" {
		t.Fatalf("unexpected discovery response: %#v", discover)
	}
	for _, frame := range frames {
		result := frame["result"].(map[string]any)
		meta, ok := result["_meta"].(map[string]any)
		if !ok || meta["io.modelcontextprotocol/serverInfo"] == nil || result["resultType"] != "complete" {
			t.Fatalf("modern response lacks required metadata: %#v", frame)
		}
	}
}

func TestServerModernDirectCallPinsEra(t *testing.T) {
	provider := fakeSecrets{
		list: func(context.Context, string) ([]client.Secret, error) { return []client.Secret{{Name: "SAFE"}}, nil },
		get:  func(context.Context, string, string) (client.Secret, error) { return client.Secret{}, nil },
	}
	server, err := New(provider, "vault-uri", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"secryn_secret_list","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
	}, "\n") + "\n"
	stdout := serveUntilFrames(t, server, input, 2)
	frames := decodeFrames(t, stdout)
	if len(frames) != 2 {
		t.Fatalf("modern direct call or cross-era rejection failed: %s", stdout)
	}
	byID := make(map[float64]map[string]any, len(frames))
	for _, frame := range frames {
		byID[frame["id"].(float64)] = frame
	}
	if byID[1]["result"] == nil || byID[2]["error"] == nil {
		t.Fatalf("modern direct call or cross-era rejection failed: %s", stdout)
	}
	errorData := byID[2]["error"].(map[string]any)["data"].(map[string]any)
	if errorData["_meta"] == nil {
		t.Fatalf("modern error lacks server metadata: %#v", byID[2])
	}
}

func TestServerModernRequiresValidMetadataAndRejectsEraMixing(t *testing.T) {
	provider := fakeSecrets{
		list: func(context.Context, string) ([]client.Secret, error) { return nil, nil },
		get:  func(context.Context, string, string) (client.Secret, error) { return client.Secret{}, nil },
	}
	tests := []struct {
		name  string
		input string
	}{
		{"missing metadata", `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}` + "\n"},
		{"wrong version", `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/clientCapabilities":{}}}}` + "\n"},
		{"missing capabilities", `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}` + "\n"},
		{"malformed client info", `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test"}}}}` + "\n"},
		{"legacy then modern", strings.Join([]string{
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
			`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
		}, "\n") + "\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, err := New(provider, "vault-uri", "test", nil)
			if err != nil {
				t.Fatal(err)
			}
			stdout := &bytes.Buffer{}
			if err := server.Serve(context.Background(), strings.NewReader(test.input), stdout); err != nil {
				t.Fatal(err)
			}
			frames := decodeFrames(t, stdout.Bytes())
			last := frames[len(frames)-1]
			if last["error"] == nil {
				t.Fatalf("expected protocol error: %s", stdout.String())
			}
			if test.name == "wrong version" {
				rpcErr := last["error"].(map[string]any)
				data := rpcErr["data"].(map[string]any)
				versions := data["supportedVersions"].([]any)
				if rpcErr["code"] != float64(-32022) || len(versions) != 1 || versions[0] != ModernProtocolVersion || data["_meta"] == nil {
					t.Fatalf("unexpected unsupported-version error: %#v", rpcErr)
				}
			}
		})
	}
}

func TestResourceToolsRequireExplicitPrivateOptIn(t *testing.T) {
	provider := fakeSecrets{
		list: func(context.Context, string) ([]client.Secret, error) { return nil, nil },
		get:  func(context.Context, string, string) (client.Secret, error) { return client.Secret{}, nil },
		getResource: func(_ context.Context, _, resourceType, name string) (secretservice.DecryptedResource, error) {
			switch resourceType {
			case "key":
				return secretservice.DecryptedResource{Name: name, Material: &secretservice.KeyMaterial{PEMPublic: "PUBLIC", PEMPrivate: "PRIVATE"}}, nil
			case "certificate":
				return secretservice.DecryptedResource{Name: name, CertificatePEM: "CERTIFICATE", PrivateKeyPEM: "CERT-PRIVATE"}, nil
			default:
				return secretservice.DecryptedResource{}, errors.New("wrong resource type")
			}
		},
	}
	tests := []struct {
		name        string
		tool        string
		arguments   string
		want        string
		mustNotHave string
	}{
		{name: "key public default", tool: "secryn_key_get", arguments: `{"name":"signing"}`, want: "PUBLIC", mustNotHave: "PRIVATE"},
		{name: "key private explicit", tool: "secryn_key_get", arguments: `{"name":"signing","include_private":true}`, want: "PRIVATE"},
		{name: "certificate public default", tool: "secryn_certificate_get", arguments: `{"name":"tls"}`, want: "CERTIFICATE", mustNotHave: "CERT-PRIVATE"},
		{name: "certificate private explicit", tool: "secryn_certificate_get", arguments: `{"name":"tls","include_private":true}`, want: "CERT-PRIVATE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, err := New(provider, "vault-uri", "test", nil)
			if err != nil {
				t.Fatal(err)
			}
			input := strings.Join([]string{
				`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
				`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
				`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + test.tool + `","arguments":` + test.arguments + `}}`,
			}, "\n") + "\n"
			stdout := serveUntilFrames(t, server, input, 2)
			if !strings.Contains(string(stdout), test.want) || (test.mustNotHave != "" && strings.Contains(string(stdout), test.mustNotHave)) {
				t.Fatalf("unexpected resource tool output: %s", stdout)
			}
		})
	}
}

func TestServerContextCancellationStopsActiveTool(t *testing.T) {
	started := make(chan struct{})
	provider := fakeSecrets{
		list: func(context.Context, string) ([]client.Secret, error) { return nil, nil },
		get: func(ctx context.Context, _, _ string) (client.Secret, error) {
			close(started)
			<-ctx.Done()
			return client.Secret{}, ctx.Err()
		},
	}
	server, err := New(provider, "vault-uri", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, reader, io.Discard) }()
	_, _ = io.WriteString(writer, strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"secryn_secret_get","arguments":{"name":"SAFE"}}}`,
	}, "\n")+"\n")
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve() after cancellation = %v", err)
	}
	_ = writer.Close()
}

func decodeFrames(t *testing.T, payload []byte) []map[string]any {
	t.Helper()
	frames := make([]map[string]any, 0)
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	for scanner.Scan() {
		var frame map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil {
			t.Fatalf("invalid JSON-RPC output: %v", err)
		}
		frames = append(frames, frame)
	}
	return frames
}

type notifyingBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	frames chan struct{}
}

func (w *notifyingBuffer) Write(payload []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buffer.Write(payload)
	w.mu.Unlock()
	if bytes.Contains(payload, []byte{'\n'}) {
		w.frames <- struct{}{}
	}
	return n, err
}

func (w *notifyingBuffer) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buffer.Bytes()...)
}

func serveUntilFrames(t *testing.T, server *Server, input string, expected int) []byte {
	t.Helper()
	reader, writer := io.Pipe()
	output := &notifyingBuffer{frames: make(chan struct{}, expected+1)}
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background(), reader, output) }()
	if _, err := io.WriteString(writer, input); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < expected; index++ {
		select {
		case <-output.frames:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for MCP frame %d; output=%s", index+1, output.Bytes())
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
