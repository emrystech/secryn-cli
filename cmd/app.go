package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/secryn/secryn-cli/internal/client"
	"github.com/secryn/secryn-cli/internal/config"
	"github.com/secryn/secryn-cli/pkg/version"
	"github.com/spf13/cobra"
)

type rootFlags struct {
	ConfigPath string
	BaseURL    string
	VaultID    string
	AccessKey  string
	JSON       bool
}

type App struct {
	stdout     io.Writer
	stderr     io.Writer
	envLookup  func(string) string
	httpClient *http.Client
	flags      rootFlags
	cfgPath    string
	runtimeCfg config.Config
}

func NewApp(stdout, stderr io.Writer) *App {
	return &App{
		stdout:     stdout,
		stderr:     stderr,
		envLookup:  os.Getenv,
		httpClient: &http.Client{},
	}
}

func Execute() int {
	app := NewApp(os.Stdout, os.Stderr)
	return app.Execute()
}

func (a *App) Execute() int {
	root := a.newRootCommand()
	if err := root.Execute(); err != nil {
		var cliErr *CLIError
		if errors.As(err, &cliErr) {
			_, _ = fmt.Fprintln(a.stderr, cliErr.Error())
			if cliErr.Code == 0 {
				return exitGeneric
			}
			return cliErr.Code
		}
		_, _ = fmt.Fprintln(a.stderr, err.Error())
		return exitGeneric
	}
	return exitOK
}

func (a *App) newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "secryn",
		Short:         "Secryn CLI for secrets, keys, and certificates",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       fmt.Sprintf("%s (commit %s, built %s)", version.Version, version.Commit, version.Date),
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return a.loadRuntimeConfig(cmd)
		},
	}

	root.PersistentFlags().StringVar(&a.flags.ConfigPath, "config", "", "Path to config file")
	root.PersistentFlags().StringVar(&a.flags.BaseURL, "base-url", "", "Secryn API base URL")
	root.PersistentFlags().StringVar(&a.flags.VaultID, "vault-id", "", "Vault ID")
	root.PersistentFlags().StringVar(&a.flags.AccessKey, "access-key", "", "Vault access key (Bearer token)")
	root.PersistentFlags().BoolVar(&a.flags.JSON, "json", false, "Output JSON")

	root.AddCommand(
		a.newConfigCommand(),
		a.newSecretCommand(),
		a.newEnvCommand(),
		a.newKeyCommand(),
		a.newCertCommand(),
		a.newAuthCommand(),
		a.newDoctorCommand(),
	)

	return root
}

func (a *App) loadRuntimeConfig(cmd *cobra.Command) error {
	cfgPath, err := config.ResolvePath(a.flags.ConfigPath, a.flagChanged(cmd, "config"), a.envLookup)
	if err != nil {
		return usageError(fmt.Sprintf("resolve config path: %v", err))
	}
	a.cfgPath = cfgPath

	fileCfg, err := config.Load(cfgPath)
	if err != nil {
		return usageError(fmt.Sprintf("load config: %v", err))
	}

	envCfg := config.Config{
		BaseURL:   strings.TrimSpace(a.envLookup("SECRYN_BASE_URL")),
		VaultID:   strings.TrimSpace(a.envLookup("SECRYN_VAULT_ID")),
		AccessKey: strings.TrimSpace(a.envLookup("SECRYN_ACCESS_KEY")),
	}
	if envCfg.BaseURL != "" {
		normalized, err := config.NormalizeBaseURL(envCfg.BaseURL)
		if err != nil {
			return usageError(fmt.Sprintf("invalid SECRYN_BASE_URL: %v", err))
		}
		envCfg.BaseURL = normalized
	}

	overrides := config.Overrides{
		BaseURL:      strings.TrimSpace(a.flags.BaseURL),
		VaultID:      strings.TrimSpace(a.flags.VaultID),
		AccessKey:    strings.TrimSpace(a.flags.AccessKey),
		BaseURLSet:   a.flagChanged(cmd, "base-url"),
		VaultIDSet:   a.flagChanged(cmd, "vault-id"),
		AccessKeySet: a.flagChanged(cmd, "access-key"),
	}
	if overrides.BaseURLSet {
		normalized, err := config.NormalizeBaseURL(overrides.BaseURL)
		if err != nil {
			return usageError(fmt.Sprintf("invalid --base-url: %v", err))
		}
		overrides.BaseURL = normalized
	}

	a.runtimeCfg = config.Merge(fileCfg, envCfg, overrides)
	return nil
}

func (a *App) flagChanged(cmd *cobra.Command, name string) bool {
	if f := cmd.Flags().Lookup(name); f != nil && f.Changed {
		return true
	}
	if f := cmd.InheritedFlags().Lookup(name); f != nil && f.Changed {
		return true
	}
	if f := cmd.Root().PersistentFlags().Lookup(name); f != nil && f.Changed {
		return true
	}
	return false
}

func (a *App) apiClient() (*client.Client, error) {
	missing := make([]string, 0, 3)
	if strings.TrimSpace(a.runtimeCfg.BaseURL) == "" {
		missing = append(missing, "base-url")
	}
	if strings.TrimSpace(a.runtimeCfg.VaultID) == "" {
		missing = append(missing, "vault-id")
	}
	if strings.TrimSpace(a.runtimeCfg.AccessKey) == "" {
		missing = append(missing, "access-key")
	}
	if len(missing) > 0 {
		return nil, usageError("missing required configuration: " + strings.Join(missing, ", ") + ". Use `secryn config set` or flags/environment variables")
	}

	cli, err := client.New(a.runtimeCfg.BaseURL, a.runtimeCfg.AccessKey, a.httpClient)
	if err != nil {
		return nil, usageError(fmt.Sprintf("invalid API configuration: %v", err))
	}
	return cli, nil
}

func (a *App) writeFile(path string, payload []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return internalError("create output directory failed", err)
	}
	if err := os.WriteFile(path, payload, mode); err != nil {
		return internalError("write output file failed", err)
	}
	return nil
}

func (a *App) context() context.Context {
	return context.Background()
}

func redactAccessKey(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	if len(token) <= 6 {
		return "******"
	}
	return token[:4] + strings.Repeat("*", len(token)-6) + token[len(token)-2:]
}
