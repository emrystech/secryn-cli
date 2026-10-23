//go:build windows

package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// execResolved starts the command and waits for it. Windows has no
// syscall.Exec, so secryn stays in front of the process, forwards interrupt
// signals, and returns the child's status.
func execResolved(path string, argv []string, env []string) error {
	command := exec.Command(path)
	command.Args = append([]string{}, argv...)
	command.Env = env
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr

	if err := command.Start(); err != nil {
		return fmt.Errorf("start %s: %w", argv[0], err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case sig := <-sigCh:
				if command.Process != nil {
					_ = command.Process.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()

	err := command.Wait()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitCode()
		if code < 0 {
			return fmt.Errorf("command %s exited without a status", argv[0])
		}
		return &childExitError{Code: code}
	}
	if err != nil {
		return fmt.Errorf("wait %s: %w", argv[0], err)
	}
	return nil
}
