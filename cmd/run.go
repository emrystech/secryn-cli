package cmd

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/secryn/secryn-cli/internal/client"
	"github.com/spf13/cobra"
)

// childExitError is a command status that must become the process exit code
// without an error message. Printing it would mix secryn diagnostics into the
// child's own success or failure.
type childExitError struct {
	Code int
}

func (e *childExitError) Error() string {
	return fmt.Sprintf("command exited with status %d", e.Code)
}

func (a *App) newRunCommand() *cobra.Command {
	var only []string
	var preserveEnv bool
	var inheritAccessKey bool

	cmd := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Run a command with vault secrets in its environment",
		Long: `Fetch secrets from the configured vault and run a command with those
secrets in its environment. Values are handed only to the child process and
are never printed.

By default, a vault secret replaces an existing environment variable of the
same name, including names such as PATH. --preserve-env keeps variables that
are already set (even when empty) and uses the vault only for names that are
missing.

SECRYN_ACCESS_KEY is removed from the child environment so the CLI credential
is not exposed. --inherit-access-key keeps it.

The command is not started if the vault cannot be read, authentication fails,
or a secret named by --only is missing. Secret names that are not valid
environment variables are skipped with a warning. --only rejects an invalid
or missing name instead of skipping it.

On Linux and macOS, secryn replaces itself with the command so signals and
the exit status belong to that command. On Windows, secryn stays in front of
the command, forwards Ctrl+C and SIGTERM, and exits with the command's
status. Child output is not masked.`,
		Example: `  secryn run -- npm run deploy
  secryn run --only DB_PASSWORD,API_TOKEN -- python migrate.py --dry-run
  secryn run --preserve-env -- ./deploy.sh`,
		DisableFlagsInUseLine: true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runCommand(cmd, args, only, preserveEnv, inheritAccessKey)
		},
	}
	cmd.Flags().StringSliceVar(&only, "only", nil, "Inject only these secrets (comma-separated or repeated)")
	cmd.Flags().BoolVar(&preserveEnv, "preserve-env", false, "Keep existing environment variables when a vault secret has the same name")
	cmd.Flags().BoolVar(&inheritAccessKey, "inherit-access-key", false, "Pass SECRYN_ACCESS_KEY through to the command")
	return cmd
}

func (a *App) runCommand(cmd *cobra.Command, args []string, only []string, preserveEnv, inheritAccessKey bool) error {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return usageError("missing command to run. Usage: secryn run [flags] -- <command> [args...]")
	}

	var filter []string
	if cmd.Flags().Changed("only") {
		parsed, err := parseOnlyNames(only)
		if err != nil {
			return err
		}
		for _, name := range parsed {
			if !validEnvName(name) {
				return usageError(fmt.Sprintf("invalid environment variable name %q", name))
			}
		}
		filter = parsed
	}

	cli, err := a.apiClient()
	if err != nil {
		return err
	}
	values, err := a.loadSecretValues(a.context(), cli)
	if err != nil {
		return err
	}

	baseEnv := osEnviron(a)
	childEnv, warnings, err := buildChildEnv(baseEnv, values, filter, preserveEnv, inheritAccessKey)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		_, _ = fmt.Fprintln(a.stderr, warning)
	}

	execFn := a.execProcess
	if execFn == nil {
		execFn = execProcess
	}
	if err := execFn(args, childEnv); err != nil {
		var childErr *childExitError
		if errors.As(err, &childErr) {
			return childErr
		}
		return &CLIError{Code: exitGeneric, ErrorCode: "command_failed", Message: err.Error(), Cause: err}
	}
	return nil
}

func osEnviron(a *App) []string {
	if a.environ != nil {
		return a.environ()
	}
	return nil
}

func (a *App) loadSecretValues(ctx context.Context, cli *client.Client) (map[string]string, error) {
	secrets, err := cli.ListSecrets(ctx, a.runtimeCfg.VaultID)
	if err != nil {
		return nil, mapAPIError(err)
	}

	values := make(map[string]string, len(secrets))
	for _, item := range secrets {
		if item.Value != "" {
			values[item.Name] = item.Value
			continue
		}
		secret, err := cli.GetSecret(ctx, a.runtimeCfg.VaultID, item.Name)
		if err != nil {
			return nil, mapAPIError(err)
		}
		values[secret.Name] = secret.Value
	}
	return values, nil
}

func parseOnlyNames(raw []string) ([]string, error) {
	seen := make(map[string]struct{}, len(raw))
	names := make([]string, 0, len(raw))
	for _, item := range raw {
		for _, part := range strings.Split(item, ",") {
			name := strings.TrimSpace(part)
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, usageError("--only requires at least one secret name")
	}
	return names, nil
}

func buildChildEnv(base []string, secrets map[string]string, filter []string, preserveEnv, inheritAccessKey bool) ([]string, []string, error) {
	selected := secrets
	if filter != nil {
		selected = make(map[string]string, len(filter))
		var missing []string
		for _, name := range filter {
			value, ok := secrets[name]
			if !ok {
				missing = append(missing, name)
				continue
			}
			if strings.IndexByte(value, 0) >= 0 {
				return nil, nil, usageError(fmt.Sprintf("secret %s contains a NUL byte and cannot be passed as an environment variable", name))
			}
			selected[name] = value
		}
		if len(missing) > 0 {
			return nil, nil, &CLIError{
				Code:      exitNotFound,
				ErrorCode: "not_found",
				Message:   "secret not found: " + strings.Join(missing, ", "),
			}
		}
	}

	envValues := make(map[string]string, len(base)+len(selected))
	order := make([]string, 0, len(base)+len(selected))
	index := make(map[string]struct{}, len(base)+len(selected))
	for _, entry := range base {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			continue
		}
		if !inheritAccessKey && key == "SECRYN_ACCESS_KEY" {
			continue
		}
		if _, exists := index[key]; exists {
			envValues[key] = value
			continue
		}
		index[key] = struct{}{}
		order = append(order, key)
		envValues[key] = value
	}

	names := make([]string, 0, len(selected))
	for name := range selected {
		names = append(names, name)
	}
	sort.Strings(names)

	var warnings []string
	for _, name := range names {
		value := selected[name]
		if strings.IndexByte(value, 0) >= 0 {
			return nil, nil, usageError(fmt.Sprintf("secret %s contains a NUL byte and cannot be passed as an environment variable", name))
		}
		if !validEnvName(name) {
			warnings = append(warnings, fmt.Sprintf("warning: skipping %s: not a valid environment variable name", name))
			continue
		}
		if preserveEnv {
			if _, exists := index[name]; exists {
				continue
			}
		}
		if _, exists := index[name]; !exists {
			index[name] = struct{}{}
			order = append(order, name)
		}
		envValues[name] = value
	}

	out := make([]string, len(order))
	for i, key := range order {
		out[i] = key + "=" + envValues[key]
	}
	return out, warnings, nil
}

func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'):
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
