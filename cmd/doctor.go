package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/secryn/secryn-cli/internal/output"
	"github.com/spf13/cobra"
)

type doctorResult struct {
	ConfigPath string   `json:"config_path"`
	ConfigFile bool     `json:"config_file"`
	Missing    []string `json:"missing"`
	AuthOK     bool     `json:"auth_ok"`
}

func (a *App) newDoctorCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run local configuration and API connectivity checks",
		RunE: func(_ *cobra.Command, _ []string) error {
			result := doctorResult{ConfigPath: a.cfgPath}

			if _, err := os.Stat(a.cfgPath); err == nil {
				result.ConfigFile = true
			}

			if strings.TrimSpace(a.runtimeCfg.BaseURL) == "" {
				result.Missing = append(result.Missing, "base-url")
			}
			if strings.TrimSpace(a.runtimeCfg.VaultID) == "" {
				result.Missing = append(result.Missing, "vault-id")
			}
			if strings.TrimSpace(a.runtimeCfg.AccessKey) == "" {
				result.Missing = append(result.Missing, "access-key")
			}

			if len(result.Missing) == 0 {
				cli, err := a.apiClient()
				if err != nil {
					return err
				}
				if err := cli.AuthTest(a.context(), a.runtimeCfg.VaultID); err != nil {
					if a.flags.JSON {
						_ = output.JSON(a.stdout, result)
					}
					return mapAPIError(err)
				}
				result.AuthOK = true
			}

			if a.flags.JSON {
				return output.JSON(a.stdout, result)
			}

			_, _ = fmt.Fprintf(a.stdout, "Config file: %s\n", a.cfgPath)
			if result.ConfigFile {
				_, _ = fmt.Fprintln(a.stdout, "Config exists: yes")
			} else {
				_, _ = fmt.Fprintln(a.stdout, "Config exists: no")
			}
			if len(result.Missing) > 0 {
				_, _ = fmt.Fprintf(a.stdout, "Missing: %s\n", strings.Join(result.Missing, ", "))
				return usageError("doctor failed: missing required configuration")
			}
			if result.AuthOK {
				_, _ = fmt.Fprintln(a.stdout, "Authentication: ok")
			}
			_, _ = fmt.Fprintln(a.stdout, "Doctor checks passed")
			return nil
		},
	}
}
