package cmd

import (
	"github.com/secryn/secryn-cli/internal/mcp"
	"github.com/secryn/secryn-cli/pkg/version"
	"github.com/spf13/cobra"
)

func (a *App) newMCPCommand() *cobra.Command {
	command := &cobra.Command{Use: "mcp", Short: "Run trusted local MCP integrations"}
	command.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "Serve locally decrypted E2EE tools over stdio",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mode, err := a.runtimeCfg.EncryptionMode()
			if err != nil {
				return usageError("invalid E2EE configuration: " + err.Error())
			}
			if mode != "e2ee" {
				return usageError("`secryn mcp serve` requires a complete E2EE identity; legacy and pending vault modes are refused")
			}
			api, err := a.apiClient()
			if err != nil {
				return err
			}
			service, cleanup, err := a.e2eeSecretService(api)
			if err != nil {
				return err
			}
			defer cleanup()
			server, err := mcp.New(service, a.runtimeCfg.VaultID, version.Version, a.stderr)
			if err != nil {
				return internalError("initialize local MCP server failed", err)
			}
			if err := server.Serve(cmd.Context(), a.stdin, a.stdout); err != nil {
				return internalError("local MCP stdio server failed", err)
			}
			return nil
		},
	})
	return command
}
