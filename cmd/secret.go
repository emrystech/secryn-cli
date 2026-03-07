package cmd

import (
	"fmt"
	"sort"

	"github.com/secryn/secryn-cli/internal/output"
	"github.com/spf13/cobra"
)

func (a *App) newSecretCommand() *cobra.Command {
	secretCmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage secrets",
	}

	var namesOnly bool
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List secrets",
		RunE: func(_ *cobra.Command, _ []string) error {
			cli, err := a.apiClient()
			if err != nil {
				return err
			}
			secrets, err := cli.ListSecrets(a.context(), a.runtimeCfg.VaultID)
			if err != nil {
				return mapAPIError(err)
			}

			sort.Slice(secrets, func(i, j int) bool {
				return secrets[i].Name < secrets[j].Name
			})

			if namesOnly {
				names := make([]string, 0, len(secrets))
				for _, s := range secrets {
					names = append(names, s.Name)
				}
				if a.flags.JSON {
					return output.JSON(a.stdout, names)
				}
				for _, name := range names {
					_, _ = fmt.Fprintln(a.stdout, name)
				}
				return nil
			}

			if a.flags.JSON {
				return output.JSON(a.stdout, secrets)
			}
			if len(secrets) == 0 {
				_, _ = fmt.Fprintln(a.stdout, "No secrets found")
				return nil
			}

			rows := make([][]string, 0, len(secrets))
			for _, secret := range secrets {
				rows = append(rows, []string{secret.Name, secret.UpdatedAt})
			}
			return output.Table(a.stdout, []string{"NAME", "UPDATED_AT"}, rows)
		},
	}
	listCmd.Flags().BoolVar(&namesOnly, "names-only", false, "Show only secret names")

	getCmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Get a secret by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cli, err := a.apiClient()
			if err != nil {
				return err
			}
			secret, err := cli.GetSecret(a.context(), a.runtimeCfg.VaultID, args[0])
			if err != nil {
				return mapAPIError(err)
			}

			if a.flags.JSON {
				return output.JSON(a.stdout, secret)
			}
			_, _ = fmt.Fprintf(a.stdout, "%s=%s\n", secret.Name, secret.Value)
			return nil
		},
	}

	secretCmd.AddCommand(listCmd, getCmd)
	return secretCmd
}
