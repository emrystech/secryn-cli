package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/secryn/secryn-cli/internal/output"
	"github.com/spf13/cobra"
)

func (a *App) newCertCommand() *cobra.Command {
	certCmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage certificates",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List certificates",
		RunE: func(_ *cobra.Command, _ []string) error {
			cli, err := a.apiClient()
			if err != nil {
				return err
			}

			certs, err := cli.ListCertificates(a.context(), a.runtimeCfg.VaultID)
			if err != nil {
				return mapAPIError(err)
			}

			sort.Slice(certs, func(i, j int) bool {
				return certs[i].ID < certs[j].ID
			})

			if a.flags.JSON {
				return output.JSON(a.stdout, certs)
			}
			if len(certs) == 0 {
				_, _ = fmt.Fprintln(a.stdout, "No certificates found")
				return nil
			}

			rows := make([][]string, 0, len(certs))
			for _, cert := range certs {
				rows = append(rows, []string{cert.ID, cert.Name, cert.ExpiresAt, cert.CreatedAt})
			}
			return output.Table(a.stdout, []string{"ID", "NAME", "EXPIRES_AT", "CREATED_AT"}, rows)
		},
	}

	var outputPath string
	downloadCmd := &cobra.Command{
		Use:   "download <id>",
		Short: "Download certificate material",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if strings.TrimSpace(outputPath) == "" {
				return usageError("--output is required")
			}
			cli, err := a.apiClient()
			if err != nil {
				return err
			}

			payload, err := cli.DownloadCertificate(a.context(), a.runtimeCfg.VaultID, args[0])
			if err != nil {
				return mapAPIError(err)
			}

			if err := a.writeFile(outputPath, payload, 0o644); err != nil {
				return err
			}

			if a.flags.JSON {
				return output.JSON(a.stdout, map[string]any{
					"id":     args[0],
					"output": outputPath,
					"bytes":  len(payload),
				})
			}
			_, _ = fmt.Fprintf(a.stdout, "Certificate %s downloaded to %s\n", args[0], outputPath)
			return nil
		},
	}
	downloadCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path")

	certCmd.AddCommand(listCmd, downloadCmd)
	return certCmd
}
