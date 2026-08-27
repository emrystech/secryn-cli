package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRunUpdatesAndVerifiesRelease(t *testing.T) {
	archive := testArchive(t, []byte("new-binary"))
	digest := sha256.Sum256(archive)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			_, _ = w.Write([]byte(`{"tag_name":"v1.0.1"}`))
		case "/download/v1.0.1/checksums.txt":
			_, _ = fmt.Fprintf(w, "%s  secryn_linux_amd64.tar.gz\n", hex.EncodeToString(digest[:]))
		case "/download/v1.0.1/secryn_linux_amd64.tar.gz":
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	executable := filepath.Join(t.TempDir(), "secryn")
	if err := os.WriteFile(executable, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	manager := testManager(server)
	result, err := manager.Run(context.Background(), Options{
		CurrentVersion: "1.0.0",
		ExecutablePath: executable,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolvedExecutable, err := filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Updated || result.LatestVersion != "v1.0.1" || result.Path != resolvedExecutable {
		t.Fatalf("result = %+v", result)
	}
	got, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new-binary" {
		t.Fatalf("executable = %q, want new-binary", got)
	}
}

func TestRunRejectsBadChecksumWithoutReplacingExecutable(t *testing.T) {
	archive := testArchive(t, []byte("new-binary"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/download/v1.0.1/checksums.txt":
			_, _ = fmt.Fprintf(w, "%064x  secryn_linux_amd64.tar.gz\n", 0)
		case "/download/v1.0.1/secryn_linux_amd64.tar.gz":
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	executable := filepath.Join(t.TempDir(), "secryn")
	if err := os.WriteFile(executable, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	manager := testManager(server)
	_, err := manager.Run(context.Background(), Options{
		CurrentVersion: "1.0.0",
		TargetVersion:  "v1.0.1",
		ExecutablePath: executable,
	})
	if err == nil {
		t.Fatal("Run() expected checksum error")
	}
	got, readErr := os.ReadFile(executable)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "old-binary" {
		t.Fatalf("executable = %q, want old-binary", got)
	}
}

func TestRunCheckOnlyDoesNotDownloadAssets(t *testing.T) {
	assetRequested := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest" {
			_, _ = w.Write([]byte(`{"tag_name":"v1.0.1"}`))
			return
		}
		assetRequested = true
		http.NotFound(w, r)
	}))
	defer server.Close()

	manager := testManager(server)
	result, err := manager.Run(context.Background(), Options{CurrentVersion: "v1.0.0", CheckOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if !result.UpdateAvailable || result.Updated || assetRequested {
		t.Fatalf("result = %+v, assetRequested = %v", result, assetRequested)
	}
}

func TestShouldUpdate(t *testing.T) {
	tests := []struct {
		current, target string
		explicit        bool
		want            bool
	}{
		{current: "v1.0.0", target: "v1.0.1", want: true},
		{current: "1.0.1", target: "v1.0.1", want: false},
		{current: "v1.1.0", target: "v1.0.1", want: false},
		{current: "dev", target: "v1.0.1", want: true},
		{current: "v1.1.0", target: "v1.0.1", explicit: true, want: true},
		{current: "v1.0.1-beta.1", target: "v1.0.1", want: true},
	}
	for _, tt := range tests {
		if got := shouldUpdate(tt.current, tt.target, tt.explicit); got != tt.want {
			t.Errorf("shouldUpdate(%q, %q, %v) = %v, want %v", tt.current, tt.target, tt.explicit, got, tt.want)
		}
	}
}

func testManager(server *httptest.Server) *Manager {
	return &Manager{
		HTTPClient:       server.Client(),
		LatestReleaseURL: server.URL + "/latest",
		ReleaseBaseURL:   server.URL + "/download",
		GOOS:             "linux",
		GOARCH:           "amd64",
	}
}

func testArchive(t *testing.T, binary []byte) []byte {
	t.Helper()
	var payload bytes.Buffer
	gz := gzip.NewWriter(&payload)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "secryn", Mode: 0o755, Size: int64(len(binary)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return payload.Bytes()
}
