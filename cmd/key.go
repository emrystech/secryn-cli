package cmd

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/secryn/secryn-cli/internal/client"
	"github.com/secryn/secryn-cli/internal/output"
	"github.com/spf13/cobra"
)

func (a *App) newKeyCommand() *cobra.Command {
	keyCmd := &cobra.Command{
		Use:   "key",
		Short: "Manage keys",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List keys",
		RunE: func(_ *cobra.Command, _ []string) error {
			cli, err := a.apiClient()
			if err != nil {
				return err
			}

			mode, err := a.runtimeCfg.EncryptionMode()
			if err != nil {
				return usageError(err.Error())
			}
			var keys []client.Key
			if mode == "legacy" {
				keys, err = cli.ListKeys(a.context(), a.runtimeCfg.VaultID)
			} else if mode == "e2ee" {
				resources, resourceErr := a.listE2EEResources(a.context(), cli, "key")
				err = resourceErr
				for _, resource := range resources {
					keys = append(keys, client.Key{ID: resource.ID, Name: resource.Name, KeyType: resource.KeyType, KeySize: resource.KeySize, KeyCurve: resource.KeyCurve, OutputFormat: resource.OutputFormat})
				}
			} else {
				return usageError("unsupported encryption mode")
			}
			if err != nil {
				return mapAPIError(err)
			}

			sort.Slice(keys, func(i, j int) bool {
				return keys[i].ID < keys[j].ID
			})

			if a.flags.JSON {
				return output.JSON(a.stdout, keys)
			}
			if len(keys) == 0 {
				_, _ = fmt.Fprintln(a.stdout, "No keys found")
				return nil
			}

			rows := make([][]string, 0, len(keys))
			for _, key := range keys {
				keyType := firstNonEmpty(key.KeyType, key.Algorithm)
				keySize := ""
				if key.KeySize > 0 {
					keySize = strconv.Itoa(key.KeySize)
				}
				rows = append(rows, []string{
					key.ID,
					key.Name,
					key.Type,
					keyType,
					keySize,
					key.OutputFormat,
				})
			}
			return output.Table(a.stdout, []string{"ID", "NAME", "TYPE", "KEY_TYPE", "KEY_SIZE", "OUTPUT_FORMAT"}, rows)
		},
	}

	var outputPath, format string
	var privateKey bool
	downloadCmd := &cobra.Command{
		Use:   "download <id>",
		Short: "Download key material",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			privateOutput := mode == "legacy"
			if mode == "legacy" {
				if cmd.Flags().Changed("format") || privateKey {
					return usageError("--format and --private require an E2EE vault")
				}
				payload, err = cli.DownloadKey(a.context(), a.runtimeCfg.VaultID, args[0])
			} else if mode == "e2ee" {
				resource, resourceErr := a.getE2EEResourceByID(a.context(), cli, "key", args[0])
				if resourceErr != nil {
					err = resourceErr
				} else {
					payload, err = selectKeyDownload(resource, format, privateKey)
					privateOutput = privateKey
				}
			} else {
				return usageError("unsupported encryption mode")
			}
			if err != nil {
				return mapAPIError(err)
			}

			modeBits := os.FileMode(0o644)
			if privateOutput {
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
			_, _ = fmt.Fprintf(a.stdout, "Key %s downloaded to %s\n", args[0], outputPath)
			return nil
		},
	}
	downloadCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path")
	downloadCmd.Flags().StringVar(&format, "format", "", "Key encoding to download: pem or ssh")
	downloadCmd.Flags().BoolVar(&privateKey, "private", false, "Download private key material instead of public material")

	keyCmd.AddCommand(listCmd, downloadCmd)
	return keyCmd
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
