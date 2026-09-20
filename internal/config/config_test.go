package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveAndLoadRoundTrip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "secryn", "config.yaml")
	want := Config{
		BaseURL:             "https://demo.secryn.io/api",
		VaultID:             "vault-1",
		AccessKey:           "token-abc",
		RecipientID:         "recipient-1",
		RecipientPrivateKey: "encoded-private-key",
	}

	if err := Save(path, want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got != want {
		t.Fatal("Load() did not preserve the saved configuration")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("file permissions = %o, want 600", mode)
		}
	}
}

func TestMergePrecedence(t *testing.T) {
	t.Parallel()

	fileCfg := Config{
		BaseURL: "https://file", VaultID: "vault-file", AccessKey: "file-token",
		RecipientID: "file-recipient", RecipientPrivateKey: "file-private",
	}
	envCfg := Config{
		BaseURL: "https://env", VaultID: "vault-env", AccessKey: "env-token",
		RecipientID: "env-recipient", RecipientPrivateKey: "env-private",
	}
	overrides := Overrides{
		BaseURL:      "https://flag",
		VaultID:      "vault-flag",
		AccessKey:    "flag-token",
		BaseURLSet:   true,
		VaultIDSet:   false,
		AccessKeySet: true,
	}

	got := Merge(fileCfg, envCfg, overrides)
	want := Config{
		BaseURL: "https://flag", VaultID: "vault-env", AccessKey: "flag-token",
		RecipientID: "env-recipient", RecipientPrivateKey: "env-private",
	}
	if got != want {
		t.Fatal("Merge() did not apply file, environment, and flag precedence")
	}
}

func TestResolvePathPrecedence(t *testing.T) {
	t.Parallel()

	path, err := ResolvePath("/tmp/flag.yaml", true, func(string) string { return "/tmp/env.yaml" })
	if err != nil {
		t.Fatalf("ResolvePath() error = %v", err)
	}
	if path != "/tmp/flag.yaml" {
		t.Fatalf("ResolvePath() = %q, want /tmp/flag.yaml", path)
	}

	path, err = ResolvePath("", false, func(string) string { return "/tmp/env.yaml" })
	if err != nil {
		t.Fatalf("ResolvePath() error = %v", err)
	}
	if path != "/tmp/env.yaml" {
		t.Fatalf("ResolvePath() = %q, want /tmp/env.yaml", path)
	}
}

func TestLoadRejectsCredentialFileWithBroadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics do not apply")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("access_key: fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() accepted a credential-bearing config readable by group or others")
	}
}
