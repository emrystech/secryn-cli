package cmd

import (
	"fmt"

	"github.com/secryn/secryn-cli/internal/output"
	"github.com/spf13/cobra"
)

func (a *App) newAuthCommand() *cobra.Command {
	authCmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication checks",
	}

	testCmd := &cobra.Command{
		Use:   "test",
		Short: "Validate API authentication",
		RunE: func(_ *cobra.Command, _ []string) error {
			cli, err := a.apiClient()
			if err != nil {
				return err
			}

			mode, err := a.testAuthentication(a.context(), cli)
			if err != nil {
				return mapAPIError(err)
			}

			if a.flags.JSON {
				return output.JSON(a.stdout, map[string]any{"ok": true, "encryption_mode": mode})
			}
			_, _ = fmt.Fprintf(a.stdout, "Authentication check passed (encryption: %s)\n", mode)
			return nil
		},
	}

	authCmd.AddCommand(testCmd)
	return authCmd
}
