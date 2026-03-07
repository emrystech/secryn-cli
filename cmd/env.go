package cmd

import (
	"fmt"

	"github.com/secryn/secryn-cli/internal/output"
	"github.com/spf13/cobra"
)

func (a *App) newEnvCommand() *cobra.Command {
	envCmd := &cobra.Command{
		Use:   "env",
		Short: "Work with .env exports",
	}

	pullCmd := &cobra.Command{
		Use:   "pull",
		Short: "Export secrets as .env format",
		RunE: func(_ *cobra.Command, _ []string) error {
			cli, err := a.apiClient()
			if err != nil {
				return err
			}

			secrets, err := cli.ListSecrets(a.context(), a.runtimeCfg.VaultID)
			if err != nil {
				return mapAPIError(err)
			}

			values := make(map[string]string, len(secrets))
			for _, item := range secrets {
				if item.Value != "" {
					values[item.Name] = item.Value
					continue
				}

				secret, err := cli.GetSecret(a.context(), a.runtimeCfg.VaultID, item.Name)
				if err != nil {
					return mapAPIError(err)
				}
				values[secret.Name] = secret.Value
			}

			if a.flags.JSON {
				return output.JSON(a.stdout, values)
			}

			_, _ = fmt.Fprint(a.stdout, output.FormatEnv(values))
			return nil
		},
	}

	envCmd.AddCommand(pullCmd)
	return envCmd
}
