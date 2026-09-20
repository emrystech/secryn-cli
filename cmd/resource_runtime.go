package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/secryn/secryn-cli/internal/client"
	secretservice "github.com/secryn/secryn-cli/internal/secrets"
)

func (a *App) listE2EEResources(ctx context.Context, api *client.Client, resourceType string) ([]secretservice.DecryptedResource, error) {
	service, cleanup, err := a.e2eeSecretService(api)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return service.ListResources(ctx, a.runtimeCfg.VaultID, resourceType)
}

func (a *App) getE2EEResourceByID(ctx context.Context, api *client.Client, resourceType, id string) (secretservice.DecryptedResource, error) {
	service, cleanup, err := a.e2eeSecretService(api)
	if err != nil {
		return secretservice.DecryptedResource{}, err
	}
	defer cleanup()
	return service.GetResourceByID(ctx, a.runtimeCfg.VaultID, resourceType, id)
}

func selectKeyDownload(resource secretservice.DecryptedResource, format string, privateKey bool) ([]byte, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = strings.ToLower(strings.TrimSpace(resource.OutputFormat))
		if format != "pem" && format != "ssh" {
			format = "pem"
		}
	}
	if format != "pem" && format != "ssh" {
		return nil, usageError("--format must be pem or ssh")
	}
	if resource.Material == nil {
		return nil, usageError(fmt.Sprintf("key has no %s material", format))
	}
	var value string
	if format == "pem" {
		if privateKey {
			value = resource.Material.PEMPrivate
		} else {
			value = resource.Material.PEMPublic
		}
	} else if privateKey {
		value = resource.Material.OpenSSHPrivate
	} else {
		value = resource.Material.OpenSSHPublic
	}
	if value == "" {
		visibility := "public"
		if privateKey {
			visibility = "private"
		}
		return nil, usageError(fmt.Sprintf("key has no %s %s material", visibility, format))
	}
	return []byte(value), nil
}
