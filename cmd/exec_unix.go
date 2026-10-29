//go:build unix

package cmd

import (
	"fmt"
	"syscall"
)

// execResolved replaces the secryn process with the command.
//
// syscall.Exec keeps the same pid, so SIGINT and SIGTERM are delivered to the
// command itself and the shell observes that command's exit status. A
// supervising exec.Cmd would have to forward signals and would keep the
// secrets in the parent until the child exits. Output masking needs that
// supervisor, so it is intentionally not implemented.
func execResolved(path string, argv []string, env []string) error {
	if err := syscall.Exec(path, argv, env); err != nil {
		return fmt.Errorf("exec %s: %w", argv[0], err)
	}
	return nil
}
