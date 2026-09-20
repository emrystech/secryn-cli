package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicallyReplacesPermissiveDestinationWithPrivateMode(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "private.pem")
	if err := os.WriteFile(destination, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (&App{}).writeFile(destination, []byte("private-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("private-material")) || info.Mode().Perm() != 0o600 {
		t.Fatalf("atomic private output = %q mode %o", payload, info.Mode().Perm())
	}
}

func TestWriteFileReplacesDestinationSymlinkWithoutFollowingIt(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.pem")
	destination := filepath.Join(directory, "private.pem")
	if err := os.WriteFile(target, []byte("target-must-not-change"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, destination); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := (&App{}).writeFile(destination, []byte("private-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	targetPayload, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	destinationInfo, err := os.Lstat(destination)
	if err != nil {
		t.Fatal(err)
	}
	destinationPayload, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(targetPayload) != "target-must-not-change" || destinationInfo.Mode()&os.ModeSymlink != 0 ||
		string(destinationPayload) != "private-material" || destinationInfo.Mode().Perm() != 0o600 {
		t.Fatalf("symlink-safe output failed: target=%q destination=%q mode=%v", targetPayload, destinationPayload, destinationInfo.Mode())
	}
}
