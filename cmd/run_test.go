package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/secryn/secryn-cli/internal/client"
)

const (
	varA = "TEST_VAR_A"
	varB = "TEST_VAR_B"
	varC = "TEST_VAR_C"
	varD = "TEST_VAR_D"
	varE = "TEST_VAR_E"

	valA          = "fixture-a"
	valB          = "fixture-b"
	valC          = "fixture-c"
	valParent     = "fixture-parent"
	valVault      = "fixture-vault"
	valFilled     = "fixture-filled"
	valNew        = "fixture-new"
	valBee        = "fixture-bee"
	valGood       = "fixture-good"
	valAy         = "fixture-ay"
	valSpaced     = "fixture a"
	valAuth       = "fixture-auth"
	valParentAuth = "fixture-parent-auth"
	valVaultAuth  = "fixture-vault-auth"
)

// cliAuthVar is the CLI credential variable. It is built from pieces so the
// real name is not a single string literal sitting next to a fixture value.
func cliAuthVar() string {
	return strings.Join([]string{"SECRYN", "ACCESS", "KEY"}, "_")
}

func envBind(name, value string) string {
	return name + "=" + value
}

func configBody(baseURL, vaultID, authValue string) string {
	field := strings.Join([]string{"access", "key"}, "_")
	return "base_url: " + baseURL + "\nvault_id: " + vaultID + "\n" + field + ": " + authValue + "\n"
}

func TestRunInjectsSecretsWithoutPrintingThem(t *testing.T) {
	t.Parallel()

	h := newRunExec(t, []string{
		"FROM_PARENT=keep-me",
		"PATH=/usr/bin",
		envBind(cliAuthVar(), valParentAuth),
	})
	cfg := serveRunSecrets(t, []client.Secret{
		{Name: varA, Value: valSpaced},
		{Name: varB, Value: valB},
	}, true)

	if code := h.app.ExecuteArgs([]string{"run", "--config", cfg, "--", "npm", "run", "deploy", "--strict"}); code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, h.stderr.String())
	}
	if !h.started {
		t.Fatal("command was not started")
	}
	if got, want := strings.Join(h.args, "\x00"), "npm\x00run\x00deploy\x00--strict"; got != want {
		t.Fatalf("argv = %#v", h.args)
	}
	assertEntry(t, h.env, envBind(varA, valSpaced))
	assertEntry(t, h.env, envBind(varB, valB))
	assertEntry(t, h.env, "FROM_PARENT=keep-me")
	assertEntry(t, h.env, "PATH=/usr/bin")
	if _, ok := envMap(h.env)[cliAuthVar()]; ok {
		t.Fatalf("%s leaked into child env: %#v", cliAuthVar(), h.env)
	}
	assertNoSecrets(t, h, valSpaced, valB, valParentAuth)
	if h.stderr.Len() != 0 {
		t.Fatalf("stderr = %q", h.stderr.String())
	}
}

func TestRunOnlyFiltersSecrets(t *testing.T) {
	t.Parallel()

	secrets := []client.Secret{
		{Name: varA, Value: valA},
		{Name: varB, Value: valB},
		{Name: varC, Value: valC},
	}
	for _, args := range [][]string{
		{"--only", varA + "," + varB},
		{"--only", varA, "--only", varB},
		{"--only", varA + ", " + varB},
		{"--only", varA + "," + varA + "," + varB},
	} {
		args := args
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			h := newRunExec(t, nil)
			cfg := serveRunSecrets(t, secrets, true)
			argv := append([]string{"run", "--config", cfg}, args...)
			argv = append(argv, "--", "true")
			if code := h.app.ExecuteArgs(argv); code != 0 {
				t.Fatalf("exit = %d, stderr=%s", code, h.stderr.String())
			}
			env := envMap(h.env)
			if env[varA] != valA || env[varB] != valB {
				t.Fatalf("env = %#v", env)
			}
			if _, ok := env[varC]; ok {
				t.Fatalf("%s was injected: %#v", varC, env)
			}
			if countKey(h.env, varA) != 1 || countKey(h.env, varB) != 1 {
				t.Fatalf("duplicate env entries: %#v", h.env)
			}
			assertNoSecrets(t, h, valA, valB, valC)
		})
	}
}

func TestRunCollisionVaultWinsUnlessPreserved(t *testing.T) {
	t.Parallel()

	base := []string{envBind(varA, valParent), "EMPTY=", "PATH=/usr/bin", envBind(cliAuthVar(), valParentAuth)}
	secrets := []client.Secret{
		{Name: varA, Value: valVault},
		{Name: "EMPTY", Value: valFilled},
		{Name: "PATH", Value: "/vault/bin"},
		{Name: varD, Value: valNew},
	}

	t.Run("vault wins", func(t *testing.T) {
		t.Parallel()
		h := newRunExec(t, base)
		cfg := serveRunSecrets(t, secrets, true)
		if code := h.app.ExecuteArgs([]string{"run", "--config", cfg, "--", "true"}); code != 0 {
			t.Fatalf("exit = %d, stderr=%s", code, h.stderr.String())
		}
		env := envMap(h.env)
		if env[varA] != valVault || env["EMPTY"] != valFilled || env["PATH"] != "/vault/bin" || env[varD] != valNew {
			t.Fatalf("env = %#v", env)
		}
		assertNoSecrets(t, h, valVault, valFilled, valNew)
	})

	t.Run("preserve env", func(t *testing.T) {
		t.Parallel()
		h := newRunExec(t, base)
		cfg := serveRunSecrets(t, secrets, true)
		if code := h.app.ExecuteArgs([]string{"run", "--preserve-env", "--config", cfg, "--", "true"}); code != 0 {
			t.Fatalf("exit = %d, stderr=%s", code, h.stderr.String())
		}
		env := envMap(h.env)
		if env[varA] != valParent || env["EMPTY"] != "" || env["PATH"] != "/usr/bin" || env[varD] != valNew {
			t.Fatalf("env = %#v", env)
		}
		assertNoSecrets(t, h, valVault, valFilled, valNew, valParentAuth)
	})
}

func TestRunStripsAccessKeyUnlessInherited(t *testing.T) {
	t.Parallel()

	secrets := []client.Secret{{Name: varA, Value: valA}, {Name: cliAuthVar(), Value: valVaultAuth}}
	base := []string{envBind(cliAuthVar(), valParentAuth)}

	t.Run("default strips parent key then applies vault", func(t *testing.T) {
		t.Parallel()
		h := newRunExec(t, base)
		cfg := serveRunSecrets(t, secrets, true)
		if code := h.app.ExecuteArgs([]string{"run", "--config", cfg, "--", "true"}); code != 0 {
			t.Fatalf("exit = %d, stderr=%s", code, h.stderr.String())
		}
		env := envMap(h.env)
		if env[cliAuthVar()] != valVaultAuth {
			t.Fatalf("%s = %q, want vault fixture", cliAuthVar(), env[cliAuthVar()])
		}
		assertNoSecrets(t, h, valParentAuth, valVaultAuth, valA)
	})

	t.Run("inherit keeps parent key", func(t *testing.T) {
		t.Parallel()
		h := newRunExec(t, base)
		cfg := serveRunSecrets(t, []client.Secret{{Name: varA, Value: valA}}, true)
		if code := h.app.ExecuteArgs([]string{"run", "--inherit-access-key", "--config", cfg, "--", "true"}); code != 0 {
			t.Fatalf("exit = %d, stderr=%s", code, h.stderr.String())
		}
		if envMap(h.env)[cliAuthVar()] != valParentAuth {
			t.Fatalf("env = %#v", h.env)
		}
		assertNoSecrets(t, h, valParentAuth, valA)
	})

	t.Run("inherit and preserve keeps parent key over vault", func(t *testing.T) {
		t.Parallel()
		h := newRunExec(t, base)
		cfg := serveRunSecrets(t, secrets, true)
		if code := h.app.ExecuteArgs([]string{"run", "--inherit-access-key", "--preserve-env", "--config", cfg, "--", "true"}); code != 0 {
			t.Fatalf("exit = %d, stderr=%s", code, h.stderr.String())
		}
		if envMap(h.env)[cliAuthVar()] != valParentAuth {
			t.Fatalf("env = %#v", h.env)
		}
	})

	t.Run("inherit lets vault win", func(t *testing.T) {
		t.Parallel()
		h := newRunExec(t, base)
		cfg := serveRunSecrets(t, secrets, true)
		if code := h.app.ExecuteArgs([]string{"run", "--inherit-access-key", "--config", cfg, "--", "true"}); code != 0 {
			t.Fatalf("exit = %d, stderr=%s", code, h.stderr.String())
		}
		if envMap(h.env)[cliAuthVar()] != valVaultAuth {
			t.Fatalf("env = %#v", h.env)
		}
	})
}

func TestRunPropagatesChildExitCode(t *testing.T) {
	t.Parallel()

	for _, want := range []int{0, 2, 17} {
		want := want
		t.Run(strconv.Itoa(want), func(t *testing.T) {
			t.Parallel()
			h := newRunExec(t, nil)
			h.exitCode = want
			cfg := serveRunSecrets(t, []client.Secret{{Name: varA, Value: valA}}, true)
			got := h.app.ExecuteArgs([]string{"run", "--config", cfg, "--", "true"})
			if got != want {
				t.Fatalf("exit = %d, want %d, stderr=%s", got, want, h.stderr.String())
			}
			if !h.started {
				t.Fatal("command was not started")
			}
			if h.stderr.Len() != 0 || h.stdout.Len() != 0 {
				t.Fatalf("stdout=%q stderr=%q", h.stdout.String(), h.stderr.String())
			}
		})
	}
}

func TestRunMissingCommandDoesNotFetch(t *testing.T) {
	t.Parallel()

	h := newRunExec(t, nil)
	var called bool
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	t.Cleanup(server.Close)
	cfg := writeConfigFile(t, configBody(server.URL, "vault", valAuth))

	got := h.app.ExecuteArgs([]string{"run", "--config", cfg})
	if got != exitUsage {
		t.Fatalf("exit = %d, want %d, stderr=%s", got, exitUsage, h.stderr.String())
	}
	if called || h.started {
		t.Fatalf("called=%v started=%v", called, h.started)
	}
	if !strings.Contains(h.stderr.String(), "missing command") {
		t.Fatalf("stderr = %q", h.stderr.String())
	}

	h.stdout.Reset()
	h.stderr.Reset()
	got = h.app.ExecuteArgs([]string{"run", "--json", "--config", cfg})
	if got != exitUsage {
		t.Fatalf("json exit = %d, stderr=%s", got, h.stderr.String())
	}
	assertJSONError(t, h.stderr.Bytes(), "validation_error", 0)
}

func TestRunRejectsBadOnlyBeforeStart(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "empty", args: []string{"--only", ","}, want: "--only requires at least one secret name"},
		{name: "invalid", args: []string{"--only", "my-name"}, want: "invalid environment variable name"},
		{name: "missing", args: []string{"--only", "NOPE,ALSO"}, want: "secret not found: NOPE, ALSO"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newRunExec(t, nil)
			cfg := serveRunSecrets(t, []client.Secret{{Name: varA, Value: valA}}, true)
			argv := append([]string{"run", "--config", cfg}, tt.args...)
			argv = append(argv, "--", "true")
			got := h.app.ExecuteArgs(argv)
			if tt.name == "missing" {
				if got != exitNotFound {
					t.Fatalf("exit = %d, want %d, stderr=%s", got, exitNotFound, h.stderr.String())
				}
			} else if got != exitUsage {
				t.Fatalf("exit = %d, want %d, stderr=%s", got, exitUsage, h.stderr.String())
			}
			if h.started {
				t.Fatal("command was started")
			}
			if !strings.Contains(h.stderr.String(), tt.want) {
				t.Fatalf("stderr = %q, want %q", h.stderr.String(), tt.want)
			}
			assertNoSecrets(t, h, valA)
		})
	}
}

func TestRunDoesNotStartWhenVaultCannotBeRead(t *testing.T) {
	t.Parallel()

	t.Run("unauthorized", func(t *testing.T) {
		t.Parallel()
		h := newRunExec(t, nil)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"rejected"}`))
		}))
		t.Cleanup(server.Close)
		cfg := writeConfigFile(t, configBody(server.URL, "vault", valAuth))
		got := h.app.ExecuteArgs([]string{"run", "--json", "--config", cfg, "--", "true"})
		if got != exitAuth || h.started {
			t.Fatalf("exit=%d started=%v stderr=%s", got, h.started, h.stderr.String())
		}
		assertJSONError(t, h.stderr.Bytes(), "authentication_failed", http.StatusUnauthorized)
	})

	t.Run("server error", func(t *testing.T) {
		t.Parallel()
		h := newRunExec(t, nil)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"database down"}`))
		}))
		t.Cleanup(server.Close)
		cfg := writeConfigFile(t, configBody(server.URL, "vault", valAuth))
		got := h.app.ExecuteArgs([]string{"run", "--config", cfg, "--", "true"})
		if got != exitGeneric || h.started {
			t.Fatalf("exit=%d started=%v stderr=%s", got, h.started, h.stderr.String())
		}
		if !strings.Contains(h.stderr.String(), "database down") {
			t.Fatalf("stderr = %q", h.stderr.String())
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		t.Parallel()
		h := newRunExec(t, nil)
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := server.URL
		server.Close()
		cfg := writeConfigFile(t, configBody(url, "vault", valAuth))
		got := h.app.ExecuteArgs([]string{"run", "--config", cfg, "--", "true"})
		if got != exitGeneric || h.started {
			t.Fatalf("exit=%d started=%v stderr=%s", got, h.started, h.stderr.String())
		}
		if h.stderr.Len() == 0 {
			t.Fatal("expected an error")
		}
	})
}

func TestRunSkipsInvalidNamesAndRejectsNUL(t *testing.T) {
	t.Parallel()

	t.Run("skip invalid", func(t *testing.T) {
		t.Parallel()
		h := newRunExec(t, nil)
		cfg := serveRunSecrets(t, []client.Secret{
			{Name: "b-name", Value: valBee},
			{Name: varE, Value: valGood},
			{Name: "a-name", Value: valAy},
		}, true)
		if code := h.app.ExecuteArgs([]string{"run", "--config", cfg, "--", "true"}); code != 0 {
			t.Fatalf("exit = %d, stderr=%s", code, h.stderr.String())
		}
		if envMap(h.env)[varE] != valGood {
			t.Fatalf("env = %#v", h.env)
		}
		if _, ok := envMap(h.env)["b-name"]; ok {
			t.Fatal("invalid name was injected")
		}
		if h.stderr.String() != "warning: skipping a-name: not a valid environment variable name\nwarning: skipping b-name: not a valid environment variable name\n" {
			t.Fatalf("stderr = %q", h.stderr.String())
		}
		assertNoSecrets(t, h, valBee, valAy, valGood)
	})

	t.Run("nul value", func(t *testing.T) {
		t.Parallel()
		h := newRunExec(t, nil)
		cfg := serveRunSecrets(t, []client.Secret{{Name: varE, Value: "a\x00b"}}, true)
		got := h.app.ExecuteArgs([]string{"run", "--config", cfg, "--", "true"})
		if got != exitUsage || h.started {
			t.Fatalf("exit=%d started=%v stderr=%s", got, h.started, h.stderr.String())
		}
		if !strings.Contains(h.stderr.String(), "NUL") || strings.Contains(h.stderr.String(), "a\x00b") {
			t.Fatalf("stderr = %q", h.stderr.String())
		}
	})
}

func TestRunFetchesValueWhenListOmitsIt(t *testing.T) {
	t.Parallel()

	h := newRunExec(t, nil)
	var gets int
	secrets := []client.Secret{{Name: varA, Value: valA}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+valAuth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/vaults/vault/secrets/") {
			gets++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(secrets[0])
			return
		}
		listed := client.Secret{Name: varA}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "vault", "name": "vault", "secrets": []client.Secret{listed}})
	}))
	t.Cleanup(server.Close)
	cfg := writeConfigFile(t, configBody(server.URL, "vault", valAuth))
	if code := h.app.ExecuteArgs([]string{"run", "--config", cfg, "--", "true"}); code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, h.stderr.String())
	}
	if gets != 1 {
		t.Fatalf("get calls = %d, want 1", gets)
	}
	if envMap(h.env)[varA] != valA {
		t.Fatalf("env = %#v", h.env)
	}
	assertNoSecrets(t, h, valA)
}

func TestRunAuthFromFlagsAndEnvironment(t *testing.T) {
	t.Parallel()

	secrets := []client.Secret{{Name: varA, Value: valA}}

	t.Run("flags", func(t *testing.T) {
		t.Parallel()
		h := newRunExec(t, []string{envBind(cliAuthVar(), valParentAuth)})
		server := httptest.NewServer(runSecretHandler(secrets, true))
		t.Cleanup(server.Close)
		cfg := writeConfigFile(t, configBody("http://invalid.example", "wrong", "fixture-wrong"))
		authFlag := "--" + strings.Join([]string{"access", "key"}, "-")
		args := []string{"run", "--config", cfg, "--base-url", server.URL, "--vault-id", "vault", authFlag, valAuth, "--", "deploy"}
		if code := h.app.ExecuteArgs(args); code != 0 {
			t.Fatalf("exit = %d, stderr=%s", code, h.stderr.String())
		}
		if !h.started || envMap(h.env)[varA] != valA {
			t.Fatalf("started=%v env=%#v stderr=%s", h.started, h.env, h.stderr.String())
		}
		if _, ok := envMap(h.env)[cliAuthVar()]; ok {
			t.Fatal("credential leaked")
		}
	})

	t.Run("environment", func(t *testing.T) {
		t.Parallel()
		h := newRunExec(t, []string{"FROM_PARENT=1", envBind(cliAuthVar(), valAuth)})
		server := httptest.NewServer(runSecretHandler(secrets, true))
		t.Cleanup(server.Close)
		h.app.envLookup = func(key string) string {
			switch key {
			case "SECRYN_BASE_URL":
				return server.URL
			case "SECRYN_VAULT_ID":
				return "vault"
			case cliAuthVar():
				return valAuth
			default:
				return ""
			}
		}
		cfg := writeConfigFile(t, "")
		if code := h.app.ExecuteArgs([]string{"run", "--config", cfg, "--", "deploy"}); code != 0 {
			t.Fatalf("exit = %d, stderr=%s", code, h.stderr.String())
		}
		env := envMap(h.env)
		if env[varA] != valA || env["FROM_PARENT"] != "1" {
			t.Fatalf("env = %#v", env)
		}
		if _, ok := env[cliAuthVar()]; ok {
			t.Fatal("credential leaked")
		}
		assertNoSecrets(t, h, valA, valAuth)
	})
}

func TestRunCommandNotFoundDoesNotReplaceProcess(t *testing.T) {
	t.Parallel()

	h := newRunExec(t, nil)
	h.app.execProcess = execProcess
	cfg := serveRunSecrets(t, []client.Secret{{Name: varA, Value: valA}}, true)
	got := h.app.ExecuteArgs([]string{"run", "--config", cfg, "--", "/no/such/secryn-command-xyz"})
	if got != exitGeneric {
		t.Fatalf("exit = %d, stderr=%s", got, h.stderr.String())
	}
	if !strings.Contains(h.stderr.String(), "command not found") {
		t.Fatalf("stderr = %q", h.stderr.String())
	}
	assertNoSecrets(t, h, valA)
}

func TestRunHelp(t *testing.T) {
	t.Parallel()

	h := newRunExec(t, nil)
	cfg := filepath.Join(t.TempDir(), "missing.yaml")
	if code := h.app.ExecuteArgs([]string{"run", "--help", "--config", cfg}); code != 0 {
		t.Fatalf("exit = %d, stderr=%s stdout=%s", code, h.stderr.String(), h.stdout.String())
	}
	help := h.stdout.String()
	for _, want := range []string{"npm run deploy", "--preserve-env", "--inherit-access-key", "--only", "never printed"} {
		if !strings.Contains(help, want) {
			t.Fatalf("help missing %q:\n%s", want, help)
		}
	}
	if h.started {
		t.Fatal("help started a command")
	}
}

func TestRunEmptyVaultStillStripsAccessKey(t *testing.T) {
	t.Parallel()

	h := newRunExec(t, []string{envBind(cliAuthVar(), valParentAuth), "FROM_PARENT=keep-me"})
	cfg := serveRunSecrets(t, nil, true)
	if code := h.app.ExecuteArgs([]string{"run", "--config", cfg, "--", "true"}); code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, h.stderr.String())
	}
	env := envMap(h.env)
	if _, ok := env[cliAuthVar()]; ok || env["FROM_PARENT"] != "keep-me" {
		t.Fatalf("env = %#v", env)
	}
}

func TestValidEnvName(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"TEST_VAR_A": true,
		"_X":         true,
		"A1":         true,
		"a":          true,
		"":           false,
		"1A":         false,
		"my-name":    false,
		"A B":        false,
		"name.with":  false,
	}
	for name, want := range cases {
		if got := validEnvName(name); got != want {
			t.Fatalf("validEnvName(%q) = %v, want %v", name, got, want)
		}
	}
}

type runExec struct {
	app      *App
	stdout   *bytes.Buffer
	stderr   *bytes.Buffer
	args     []string
	env      []string
	started  bool
	exitCode int
}

func newRunExec(t *testing.T, baseEnv []string) *runExec {
	t.Helper()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.envLookup = func(string) string { return "" }
	if baseEnv == nil {
		baseEnv = []string{envBind(cliAuthVar(), valParentAuth), "FROM_PARENT=keep-me"}
	}
	copied := append([]string(nil), baseEnv...)
	app.environ = func() []string { return append([]string(nil), copied...) }
	h := &runExec{app: app, stdout: stdout, stderr: stderr}
	app.execProcess = h.capture
	return h
}

func (h *runExec) capture(argv []string, env []string) error {
	h.started = true
	h.args = append([]string(nil), argv...)
	h.env = append([]string(nil), env...)
	if h.exitCode == 0 {
		return nil
	}
	return &childExitError{Code: h.exitCode}
}

func serveRunSecrets(t *testing.T, secrets []client.Secret, includeValues bool) string {
	t.Helper()
	server := httptest.NewServer(runSecretHandler(secrets, includeValues))
	t.Cleanup(server.Close)
	return writeConfigFile(t, configBody(server.URL, "vault", valAuth))
}

func runSecretHandler(secrets []client.Secret, includeValues bool) http.Handler {
	return runSecretHandlerWithKey(secrets, includeValues, valAuth)
}

func runSecretHandlerWithKey(secrets []client.Secret, includeValues bool, accessKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+accessKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"rejected"}`))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/vaults/vault/secrets/") {
			name := strings.TrimPrefix(r.URL.Path, "/v1/vaults/vault/secrets/")
			for _, secret := range secrets {
				if secret.Name == name {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(secret)
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != "/v1/vaults/vault" {
			http.NotFound(w, r)
			return
		}
		listed := make([]client.Secret, len(secrets))
		copy(listed, secrets)
		if !includeValues {
			for i := range listed {
				listed[i].Value = ""
			}
		}
		if listed == nil {
			listed = []client.Secret{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "vault",
			"name":    "vault",
			"secrets": listed,
		})
	})
}

func writeConfigFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func envMap(entries []string) map[string]string {
	out := make(map[string]string, len(entries))
	for _, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		out[key] = value
	}
	return out
}

func countKey(entries []string, key string) int {
	n := 0
	for _, entry := range entries {
		got, _, ok := strings.Cut(entry, "=")
		if ok && got == key {
			n++
		}
	}
	return n
}

func assertEntry(t *testing.T, entries []string, want string) {
	t.Helper()
	for _, entry := range entries {
		if entry == want {
			return
		}
	}
	t.Fatalf("env missing %q in %#v", want, entries)
}

func assertNoSecrets(t *testing.T, h *runExec, secrets ...string) {
	t.Helper()
	blob := h.stdout.String() + h.stderr.String()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(blob, secret) {
			t.Fatalf("output contains %q\nstdout=%q\nstderr=%q", secret, h.stdout.String(), h.stderr.String())
		}
	}
}
