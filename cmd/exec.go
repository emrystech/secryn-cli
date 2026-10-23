package cmd

import (
	"fmt"
	"os/exec"
	"strings"
)

// execProcess resolves argv[0] and replaces or starts the command with env.
// env must be the complete child environment. A nil slice is treated as empty
// so the parent environment, including SECRYN_ACCESS_KEY, is not inherited by
// accident (syscall.Exec keeps the current environment when envv is nil).
func execProcess(argv []string, env []string) error {
	if len(argv) == 0 || strings.TrimSpace(argv[0]) == "" {
		return fmt.Errorf("command not found")
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("command not found: %s", argv[0])
	}
	if env == nil {
		env = []string{}
	}
	return execResolved(path, argv, env)
}
