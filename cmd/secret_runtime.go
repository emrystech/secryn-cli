package cmd

import (
	"context"
	"fmt"

	"github.com/secryn/secryn-cli/internal/client"
	"github.com/secryn/secryn-cli/internal/identity"
	secretservice "github.com/secryn/secryn-cli/internal/secrets"
)

func (a *App) listSecrets(ctx context.Context, apiClient *client.Client) ([]client.Secret, error) {
	mode, err := a.runtimeCfg.EncryptionMode()
	if err != nil {
		return nil, usageError("invalid E2EE configuration: " + err.Error())
	}
	if mode == "legacy" {
		return apiClient.ListSecrets(ctx, a.runtimeCfg.VaultID)
	}
	service, cleanup, err := a.e2eeSecretService(apiClient)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return service.List(ctx, a.runtimeCfg.VaultID)
}

func (a *App) getSecret(ctx context.Context, apiClient *client.Client, name string) (client.Secret, error) {
	mode, err := a.runtimeCfg.EncryptionMode()
	if err != nil {
		return client.Secret{}, usageError("invalid E2EE configuration: " + err.Error())
	}
	if mode == "legacy" {
		return apiClient.GetSecret(ctx, a.runtimeCfg.VaultID, name)
	}
	service, cleanup, err := a.e2eeSecretService(apiClient)
	if err != nil {
		return client.Secret{}, err
	}
	defer cleanup()
	return service.Get(ctx, a.runtimeCfg.VaultID, name)
}

func (a *App) testAuthentication(ctx context.Context, apiClient *client.Client) (string, error) {
	mode, err := a.runtimeCfg.EncryptionMode()
	if err != nil {
		return "", usageError("invalid E2EE configuration: " + err.Error())
	}
	if mode == "legacy" {
		return mode, apiClient.AuthTest(ctx, a.runtimeCfg.VaultID)
	}
	service, cleanup, err := a.e2eeSecretService(apiClient)
	if err != nil {
		return mode, err
	}
	defer cleanup()
	return mode, service.Test(ctx, a.runtimeCfg.VaultID)
}

func (a *App) e2eeSecretService(apiClient *client.Client) (*secretservice.E2EEService, func(), error) {
	recipientIdentity, err := identity.Parse(a.runtimeCfg.RecipientID, a.runtimeCfg.RecipientPrivateKey)
	if err != nil {
		return nil, func() {}, usageError(fmt.Sprintf("invalid E2EE identity: %v", err))
	}
	service, err := secretservice.NewE2EE(apiClient, recipientIdentity)
	if err != nil {
		recipientIdentity.Destroy()
		return nil, func() {}, internalError("initialize E2EE secret service failed", err)
	}
	return service, recipientIdentity.Destroy, nil
}
