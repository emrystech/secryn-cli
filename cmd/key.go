package cmd

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

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

			keys, err := cli.ListKeys(a.context(), a.runtimeCfg.VaultID)
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

	var outputPath string
	downloadCmd := &cobra.Command{
		Use:   "download <id>",
		Short: "Download key material",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if strings.TrimSpace(outputPath) == "" {
				return usageError("--output is required")
			}
			cli, err := a.apiClient()
			if err != nil {
				return err
			}

			payload, err := cli.DownloadKey(a.context(), a.runtimeCfg.VaultID, args[0])
			if err != nil {
				return mapAPIError(err)
			}

			if err := a.writeFile(outputPath, payload, 0o600); err != nil {
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
