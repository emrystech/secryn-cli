package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/secryn/secryn-cli/internal/output"
	"github.com/secryn/secryn-cli/internal/updater"
	"github.com/secryn/secryn-cli/pkg/version"
	"github.com/spf13/cobra"
)

func (a *App) newUpdateCommand() *cobra.Command {
	var targetVersion string
	var checkOnly bool
	var force bool
	cmd := &cobra.Command{
		Use:         "update",
		Short:       "Update secryn to the latest release",
		Annotations: map[string]string{skipConfigAnnotation: "true"},
		RunE: func(_ *cobra.Command, _ []string) error {
			if checkOnly && force {
				return usageError("--check and --force cannot be used together")
			}
			if targetVersion != "" {
				if err := updater.ValidateVersion(targetVersion); err != nil {
					return usageError(err.Error())
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			executable, err := os.Executable()
			if err != nil {
				return internalError("locate current executable failed", err)
			}
			result, err := updater.New(a.httpClient).Run(ctx, updater.Options{
				CurrentVersion: version.Version,
				TargetVersion:  targetVersion,
				ExecutablePath: executable,
				CheckOnly:      checkOnly,
				Force:          force,
			})
			if err != nil {
				return internalError("update failed", err)
			}
			if a.flags.JSON {
				return output.JSON(a.stdout, result)
			}
			if checkOnly {
				if result.UpdateAvailable {
					_, _ = fmt.Fprintf(a.stdout, "Update available: %s -> %s\n", result.CurrentVersion, result.LatestVersion)
				} else {
					_, _ = fmt.Fprintf(a.stdout, "secryn is up to date (%s)\n", result.CurrentVersion)
				}
				return nil
			}
			if result.Updated {
				_, _ = fmt.Fprintf(a.stdout, "Updated secryn from %s to %s at %s\n", result.CurrentVersion, result.LatestVersion, result.Path)
				return nil
			}
			_, _ = fmt.Fprintf(a.stdout, "secryn is already up to date (%s)\n", result.CurrentVersion)
			return nil
		},
		Args: cobra.NoArgs,
	}
	cmd.Flags().StringVar(&targetVersion, "version", "", "Install a specific release (for example v1.0.1)")
	cmd.Flags().BoolVar(&checkOnly, "check", false, "Check for an update without installing it")
	cmd.Flags().BoolVar(&force, "force", false, "Reinstall even when the selected version is already installed")
	return cmd
}
