//go:build unix

package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/secryn/secryn-cli/internal/client"
)

const (
	runAccessKey  = "access-key-do-not-leak-9f3a"
	runVaultValue = "vault-value-9f3c2a"
)

func TestRunUnixExecInjectsEnvAndPropagatesStatus(t *testing.T) {
	if os.Getenv("SECRYN_RUN_HELPER") == "1" || os.Getenv("SECRYN_CHILD_HELPER") == "1" {
		t.Fatal("helper mode leaked into the parent test")
	}

	cfg := writeUnixRunConfig(t)
	cmd := spawnRunHelper(t, cfg, "stdio")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = strings.NewReader("hello-stdin")

	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		t.Fatalf("exit err=%v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	out := stdout.String()
	combined := out + stderr.String()
	if strings.Count(combined, runVaultValue) != 1 {
		t.Fatalf("vault value count = %d, want 1\nstdout=%s\nstderr=%s", strings.Count(combined, runVaultValue), out, stderr.String())
	}
	if strings.Contains(combined, runAccessKey) {
		t.Fatalf("access key leaked\nstdout=%s\nstderr=%s", out, stderr.String())
	}
	if !strings.Contains(out, "DB_PASSWORD="+runVaultValue+"\n") {
		t.Fatalf("stdout = %s", out)
	}
	if !strings.Contains(out, "SECRYN_ACCESS_KEY=\n") {
		t.Fatalf("access key was not stripped, stdout=%s", out)
	}
	if !strings.Contains(out, "STDIN=hello-stdin\n") {
		t.Fatalf("stdin was not passed through, stdout=%s", out)
	}
	if !strings.Contains(stderr.String(), "STDERR=ok\n") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestRunUnixExecDeliversSignalToChild(t *testing.T) {
	if os.Getenv("SECRYN_RUN_HELPER") == "1" || os.Getenv("SECRYN_CHILD_HELPER") == "1" {
		t.Fatal("helper mode leaked into the parent test")
	}

	cfg := writeUnixRunConfig(t)
	cmd := spawnRunHelper(t, cfg, "signal")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	var output bytes.Buffer
	var outputMu sync.Mutex
	ready := make(chan struct{})
	var readyOnce sync.Once
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		reader := bufio.NewReader(stdout)
		for {
			line, readErr := reader.ReadString('\n')
			outputMu.Lock()
			output.WriteString(line)
			outputMu.Unlock()
			if strings.Contains(line, "READY") {
				readyOnce.Do(func() { close(ready) })
			}
			if readErr != nil {
				return
			}
		}
	}()

	select {
	case <-ready:
	case <-time.After(15 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		<-readDone
		outputMu.Lock()
		defer outputMu.Unlock()
		t.Fatalf("timeout waiting for READY\nstdout=%s\nstderr=%s", output.String(), stderr.String())
	}

	if cmdline, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", cmd.Process.Pid)); readErr == nil {
		if !bytes.Contains(cmdline, []byte("TestSecrynRunChildHelper")) {
			t.Fatalf("process was not replaced with the child, cmdline=%q", cmdline)
		}
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	<-readDone

	var exitErr *exec.ExitError
	outputMu.Lock()
	out := output.String()
	outputMu.Unlock()
	if !errors.As(waitErr, &exitErr) || exitErr.ExitCode() != 42 {
		t.Fatalf("wait=%v\nstdout=%s\nstderr=%s", waitErr, out, stderr.String())
	}
	if !strings.Contains(out, "CAUGHT") {
		t.Fatalf("child did not observe SIGTERM, stdout=%s stderr=%s", out, stderr.String())
	}
	if strings.Contains(out+stderr.String(), runVaultValue) || strings.Contains(out+stderr.String(), runAccessKey) {
		t.Fatalf("secret leaked\nstdout=%s\nstderr=%s", out, stderr.String())
	}
}

func TestSecrynRunExecHelper(t *testing.T) {
	if os.Getenv("SECRYN_RUN_HELPER") != "1" {
		t.Skip()
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	app := NewApp(os.Stdout, os.Stderr)
	os.Exit(app.ExecuteArgs([]string{
		"run",
		"--config", os.Getenv("SECRYN_HELPER_CONFIG"),
		"--",
		exe,
		"-test.run=^TestSecrynRunChildHelper$",
	}))
}

func TestSecrynRunChildHelper(t *testing.T) {
	if os.Getenv("SECRYN_CHILD_HELPER") != "1" {
		t.Skip()
	}
	switch os.Getenv("SECRYN_CHILD_MODE") {
	case "signal":
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM)
		fmt.Println("READY")
		<-sigCh
		fmt.Println("CAUGHT")
		os.Exit(42)
	default:
		in, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("DB_PASSWORD=%s\n", os.Getenv("DB_PASSWORD"))
		fmt.Printf("SECRYN_ACCESS_KEY=%s\n", os.Getenv("SECRYN_ACCESS_KEY"))
		fmt.Printf("STDIN=%s\n", in)
		fmt.Fprintln(os.Stderr, "STDERR=ok")
		os.Exit(7)
	}
}

func writeUnixRunConfig(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(runSecretHandlerWithKey([]client.Secret{{
		Name:  "DB_PASSWORD",
		Value: runVaultValue,
	}}, true, runAccessKey))
	t.Cleanup(server.Close)
	return writeConfigFile(t, "base_url: "+server.URL+"\nvault_id: vault\naccess_key: "+runAccessKey+"\n")
}

func spawnRunHelper(t *testing.T, cfg, mode string) *exec.Cmd {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestSecrynRunExecHelper$")
	command.Env = helperEnviron(cfg, mode)
	return command
}

func helperEnviron(cfg, mode string) []string {
	env := make([]string, 0, len(os.Environ())+5)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "SECRYN_") {
			continue
		}
		env = append(env, entry)
	}
	return append(env,
		"SECRYN_RUN_HELPER=1",
		"SECRYN_CHILD_HELPER=1",
		"SECRYN_CHILD_MODE="+mode,
		"SECRYN_HELPER_CONFIG="+cfg,
		"SECRYN_ACCESS_KEY="+runAccessKey,
	)
}
