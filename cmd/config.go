package cmd

import (
	"fmt"
	"strings"

	"github.com/secryn/secryn-cli/internal/config"
	"github.com/secryn/secryn-cli/internal/output"
	"github.com/spf13/cobra"
)

func (a *App) newConfigCommand() *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage local Secryn CLI configuration",
	}

	configCmd.AddCommand(
		a.newConfigSetCommand(),
		a.newConfigShowCommand(),
	)

	return configCmd
}

func (a *App) newConfigSetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "set",
		Short: "Save base URL, vault ID, and access key in config file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			baseChanged := a.flagChanged(cmd, "base-url")
			vaultChanged := a.flagChanged(cmd, "vault-id")
			accessChanged := a.flagChanged(cmd, "access-key")
			if !baseChanged && !vaultChanged && !accessChanged {
				return usageError("no values provided. Pass at least one of --base-url, --vault-id, --access-key")
			}

			cfg, err := config.Load(a.cfgPath)
			if err != nil {
				return internalError("load existing config failed", err)
			}

			if baseChanged {
				normalized, err := config.NormalizeBaseURL(strings.TrimSpace(a.flags.BaseURL))
				if err != nil {
					return usageError(fmt.Sprintf("invalid --base-url: %v", err))
				}
				cfg.BaseURL = normalized
			}
			if vaultChanged {
				cfg.VaultID = strings.TrimSpace(a.flags.VaultID)
			}
			if accessChanged {
				cfg.AccessKey = strings.TrimSpace(a.flags.AccessKey)
			}

			if err := config.Save(a.cfgPath, cfg); err != nil {
				return internalError("save config failed", err)
			}

			a.runtimeCfg = cfg
			if a.flags.JSON {
				return output.JSON(a.stdout, map[string]any{
					"config_path": a.cfgPath,
					"updated":     true,
				})
			}
			_, _ = fmt.Fprintf(a.stdout, "Configuration saved to %s\n", a.cfgPath)
			return nil
		},
	}
}

func (a *App) newConfigShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show effective configuration",
		RunE: func(_ *cobra.Command, _ []string) error {
			view := map[string]string{
				"config_path": a.cfgPath,
				"base_url":    a.runtimeCfg.BaseURL,
				"vault_id":    a.runtimeCfg.VaultID,
				"access_key":  redactAccessKey(a.runtimeCfg.AccessKey),
			}
			if a.flags.JSON {
				return output.JSON(a.stdout, view)
			}

			_, _ = fmt.Fprintf(a.stdout, "Config File: %s\n", view["config_path"])
			_, _ = fmt.Fprintf(a.stdout, "Base URL:    %s\n", valueOrPlaceholder(view["base_url"]))
			_, _ = fmt.Fprintf(a.stdout, "Vault ID:    %s\n", valueOrPlaceholder(view["vault_id"]))
			_, _ = fmt.Fprintf(a.stdout, "Access Key:  %s\n", valueOrPlaceholder(view["access_key"]))
			return nil
		},
	}
}

func valueOrPlaceholder(v string) string {
	if strings.TrimSpace(v) == "" {
		return "<not set>"
	}
	return v
}
