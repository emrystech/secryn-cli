package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/secryn/secryn-cli/internal/client"
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

			mode, err := a.runtimeCfg.EncryptionMode()
			if err != nil {
				return usageError(err.Error())
			}
			var certs []client.Certificate
			if mode == "legacy" {
				certs, err = cli.ListCertificates(a.context(), a.runtimeCfg.VaultID)
			} else if mode == "e2ee" {
				resources, resourceErr := a.listE2EEResources(a.context(), cli, "certificate")
				err = resourceErr
				for _, resource := range resources {
					certs = append(certs, client.Certificate{ID: resource.ID, Name: resource.Name})
				}
			} else {
				return usageError("unsupported encryption mode")
			}
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
				rows = append(rows, []string{cert.ID, cert.Name, cert.Type, cert.ExpiresAt})
			}
			return output.Table(a.stdout, []string{"ID", "NAME", "TYPE", "EXPIRES_AT"}, rows)
		},
	}

	var outputPath string
	var privateKey bool
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

			mode, err := a.runtimeCfg.EncryptionMode()
			if err != nil {
				return usageError(err.Error())
			}
			var payload []byte
			if mode == "legacy" {
				if privateKey {
					return usageError("--private-key requires an E2EE vault")
				}
				payload, err = cli.DownloadCertificate(a.context(), a.runtimeCfg.VaultID, args[0])
			} else if mode == "e2ee" {
				resource, resourceErr := a.getE2EEResourceByID(a.context(), cli, "certificate", args[0])
				if resourceErr != nil {
					err = resourceErr
				} else if privateKey {
					if resource.PrivateKeyPEM == "" {
						return usageError("certificate has no private key material")
					}
					payload = []byte(resource.PrivateKeyPEM)
				} else {
					payload = []byte(resource.CertificatePEM)
				}
			} else {
				return usageError("unsupported encryption mode")
			}
			if err != nil {
				return mapAPIError(err)
			}

			modeBits := os.FileMode(0o644)
			if privateKey {
				modeBits = 0o600
			}
			if err := a.writeFile(outputPath, payload, modeBits); err != nil {
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
	downloadCmd.Flags().BoolVar(&privateKey, "private-key", false, "Download private key material instead of the certificate")

	certCmd.AddCommand(listCmd, downloadCmd)
	return certCmd
}
