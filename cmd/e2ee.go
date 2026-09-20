package cmd

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/secryn/secryn-cli/internal/client"
	"github.com/secryn/secryn-cli/internal/config"
	secryncrypto "github.com/secryn/secryn-cli/internal/crypto"
	"github.com/secryn/secryn-cli/internal/identity"
	"github.com/secryn/secryn-cli/internal/output"
	"github.com/spf13/cobra"
)

var lifecycleBase64URL = base64.RawURLEncoding.Strict()

func (a *App) newE2EECommand() *cobra.Command {
	command := &cobra.Command{Use: "e2ee", Short: "Manage end-to-end encryption lifecycle"}
	command.AddCommand(a.newE2EEInitCommand(), a.newE2EERecipientCommand(), a.newE2EERotateCommand(), a.newE2EERotationCommand())
	return command
}

func (a *App) newE2EEInitCommand() *cobra.Command {
	var label, recipientType string
	command := &cobra.Command{
		Use: "init", Short: "Enable E2EE on an eligible empty legacy vault",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireFileBackedLifecycleConfig(cmd, false); err != nil {
				return err
			}
			api, err := a.apiClient()
			if err != nil {
				return err
			}
			fileConfig, err := config.Load(a.cfgPath)
			if err != nil {
				return internalError("load bootstrap configuration failed", err)
			}
			mode, err := fileConfig.EncryptionMode()
			if err != nil {
				return usageError(err.Error())
			}
			cryptoContext, err := api.GetCryptoContext(a.context(), a.runtimeCfg.VaultID)
			if err != nil {
				if mode == "e2ee_pending" {
					return internalError("bootstrap recovery could not inspect server state; the pending identity was retained. Rerun `secryn e2ee init`", err)
				}
				return mapAPIError(err)
			}
			if mode == "e2ee_pending" && cryptoContext.EncryptionMode == "e2ee" {
				return a.recoverPendingBootstrap(api, cryptoContext, fileConfig)
			}
			if cryptoContext.EncryptionMode != "legacy" || !cryptoContext.BootstrapEligible {
				return usageError("vault is not eligible for E2EE bootstrap; any pending identity was retained for recovery")
			}

			originalConfig := fileConfig
			newlyStaged := mode == "legacy"
			var recipientID string
			var privateKey, publicKey []byte
			if newlyStaged {
				keyPair, err := secryncrypto.GenerateRecipientKeyPair()
				if err != nil {
					return internalError("generate recipient identity failed", err)
				}
				privateKey, publicKey = keyPair.PrivateKey, keyPair.PublicKey
				recipientID, err = randomUUID()
				if err != nil {
					wipeBytes(privateKey)
					return internalError("generate recipient ID failed", err)
				}
				fileConfig.RecipientID = recipientID
				fileConfig.RecipientPrivateKey = lifecycleBase64URL.EncodeToString(privateKey)
				fileConfig.E2EEBootstrapPending = true
			} else {
				recipientID = fileConfig.RecipientID
				privateKey, err = lifecycleBase64URL.DecodeString(fileConfig.RecipientPrivateKey)
				if err != nil || len(privateKey) != 32 {
					return usageError("pending bootstrap identity is malformed")
				}
				publicKey, err = secryncrypto.RecipientPublicKey(privateKey)
				if err != nil {
					wipeBytes(privateKey)
					return usageError("pending bootstrap identity is malformed")
				}
			}
			defer wipeBytes(privateKey)
			vek := make([]byte, secryncrypto.VEKSize)
			if _, err := cryptorand.Read(vek); err != nil {
				return internalError("generate vault encryption key failed", err)
			}
			defer wipeBytes(vek)
			envelope, err := secryncrypto.WrapVEKForRecipient(vek, publicKey, secryncrypto.RecipientContext{
				VaultID: cryptoContext.VaultID, RecipientID: recipientID, KeyVersion: 1,
			})
			if err != nil {
				return internalError("wrap vault key failed", err)
			}
			request := provisionRequest(recipientID, recipientType, label, publicKey, *envelope)
			if newlyStaged {
				if err := config.Save(a.cfgPath, fileConfig); err != nil {
					return internalError("securely stage recipient identity before bootstrap failed; no request was sent", err)
				}
			}
			result, err := api.BootstrapE2EE(a.context(), a.runtimeCfg.VaultID, request)
			if err != nil {
				if newlyStaged && definitiveBootstrapRejection(err) {
					if restoreErr := config.Save(a.cfgPath, originalConfig); restoreErr != nil {
						return internalError("bootstrap was rejected but restoring the original config failed; the staged identity was retained", restoreErr)
					}
					return mapAPIError(err)
				}
				return internalError("bootstrap outcome is unknown; the pending identity was retained. Rerun `secryn e2ee init` to reconcile safely", err)
			}
			if result.EncryptionMode != "e2ee" || result.KeyVersion != 1 || result.VaultID != cryptoContext.VaultID {
				return internalError("bootstrap response could not be verified; the pending identity was retained. Rerun `secryn e2ee init` to reconcile safely", nil)
			}
			fileConfig.E2EEBootstrapPending = false
			if err := config.Save(a.cfgPath, fileConfig); err != nil {
				return internalError("E2EE enabled and the identity is retained as pending; rerun `secryn e2ee init` to finalize recovery", err)
			}
			if a.flags.JSON {
				return output.JSON(a.stdout, map[string]any{"ok": true, "encryption_mode": "e2ee", "recipient_id": recipientID})
			}
			_, _ = fmt.Fprintf(a.stdout, "E2EE enabled; recipient %s saved securely in %s\n", recipientID, a.cfgPath)
			return nil
		},
	}
	command.Flags().StringVar(&label, "label", "Secryn CLI", "Recipient label")
	command.Flags().StringVar(&recipientType, "type", "cli", "Recipient type")
	return command
}

func (a *App) newE2EERecipientCommand() *cobra.Command {
	command := &cobra.Command{Use: "recipient", Short: "Manage E2EE recipients"}
	command.AddCommand(a.newE2EERecipientListCommand(), a.newE2EERecipientAddCommand(), a.newE2EERecipientRevokeCommand())
	return command
}

func (a *App) newE2EERecipientListCommand() *cobra.Command {
	return &cobra.Command{Use: "list", RunE: func(_ *cobra.Command, _ []string) error {
		api, err := a.apiClient()
		if err != nil {
			return err
		}
		if _, err := a.canonicalLifecycleVault(api); err != nil {
			return mapAPIError(err)
		}
		items, err := api.ListRecipients(a.context(), a.runtimeCfg.VaultID)
		if err != nil {
			return mapAPIError(err)
		}
		if a.flags.JSON {
			return output.JSON(a.stdout, items)
		}
		rows := make([][]string, 0, len(items))
		for _, item := range items {
			rows = append(rows, []string{item.ID, item.Type, item.Label, item.Status})
		}
		return output.Table(a.stdout, []string{"ID", "TYPE", "LABEL", "STATUS"}, rows)
	}}
}

func (a *App) newE2EERecipientAddCommand() *cobra.Command {
	var id, recipientType, label, publicKey string
	command := &cobra.Command{Use: "add", RunE: func(_ *cobra.Command, _ []string) error {
		if !validLifecycleUUID(id) {
			return usageError("--id must be a valid UUID")
		}
		api, err := a.apiClient()
		if err != nil {
			return err
		}
		vek, vaultID, keyVersion, cleanup, err := a.unlockLifecycleVault(api)
		if err != nil {
			return mapAPIError(err)
		}
		defer cleanup()
		publicBytes, err := lifecycleBase64URL.DecodeString(publicKey)
		if err != nil || len(publicBytes) != 32 {
			return usageError("--public-key must be an unpadded Base64URL 32-byte X25519 public key")
		}
		envelope, err := secryncrypto.WrapVEKForRecipient(vek, publicBytes, secryncrypto.RecipientContext{VaultID: vaultID, RecipientID: id, KeyVersion: keyVersion})
		if err != nil {
			return internalError("wrap vault key for recipient failed", err)
		}
		result, err := api.AddRecipient(a.context(), a.runtimeCfg.VaultID, provisionRequest(id, recipientType, label, publicBytes, *envelope))
		if err != nil {
			return mapAPIError(err)
		}
		if a.flags.JSON {
			return output.JSON(a.stdout, result)
		}
		_, _ = fmt.Fprintf(a.stdout, "Recipient %s added\n", id)
		return nil
	}}
	command.Flags().StringVar(&id, "id", "", "Recipient UUID")
	command.Flags().StringVar(&recipientType, "type", "service", "Recipient type")
	command.Flags().StringVar(&label, "label", "", "Recipient label")
	command.Flags().StringVar(&publicKey, "public-key", "", "Recipient X25519 public key (Base64URL)")
	_ = command.MarkFlagRequired("id")
	_ = command.MarkFlagRequired("label")
	_ = command.MarkFlagRequired("public-key")
	return command
}

func (a *App) newE2EERecipientRevokeCommand() *cobra.Command {
	var allowSelf bool
	command := &cobra.Command{Use: "revoke <recipient-id>", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		if args[0] == a.runtimeCfg.RecipientID && !allowSelf {
			return usageError("refusing self-revocation without --allow-self; this identity will immediately lose vault access")
		}
		api, err := a.apiClient()
		if err != nil {
			return err
		}
		if _, err := a.canonicalLifecycleVault(api); err != nil {
			return mapAPIError(err)
		}
		if err := api.RevokeRecipient(a.context(), a.runtimeCfg.VaultID, args[0]); err != nil {
			return mapAPIError(err)
		}
		if args[0] == a.runtimeCfg.RecipientID {
			_, _ = fmt.Fprintln(a.stderr, "Warning: the configured recipient identity has been revoked")
		}
		if a.flags.JSON {
			return output.JSON(a.stdout, map[string]any{"ok": true, "recipient_id": args[0]})
		}
		_, _ = fmt.Fprintf(a.stdout, "Recipient %s revoked\n", args[0])
		return nil
	}}
	command.Flags().BoolVar(&allowSelf, "allow-self", false, "Allow revoking the currently configured recipient")
	return command
}

func (a *App) newE2EERotateCommand() *cobra.Command {
	return &cobra.Command{Use: "rotate", RunE: func(_ *cobra.Command, _ []string) error {
		api, err := a.apiClient()
		if err != nil {
			return err
		}
		oldVEK, vaultID, oldVersion, cleanup, err := a.unlockLifecycleVault(api)
		if err != nil {
			return mapAPIError(err)
		}
		defer cleanup()
		recipients, err := api.ListRecipients(a.context(), a.runtimeCfg.VaultID)
		if err != nil {
			return mapAPIError(err)
		}
		newVEK := make([]byte, secryncrypto.VEKSize)
		if _, err := cryptorand.Read(newVEK); err != nil {
			return internalError("generate rotated vault key failed", err)
		}
		defer wipeBytes(newVEK)
		targetVersion := oldVersion + 1
		envelopes := make([]client.RecipientEnvelopeWrite, 0, len(recipients))
		for _, recipient := range recipients {
			if recipient.Status != "active" {
				continue
			}
			publicKey, err := lifecycleBase64URL.DecodeString(recipient.PublicKey)
			if err != nil || len(publicKey) != 32 {
				return internalError("recipient list contains an invalid public key", nil)
			}
			envelope, err := secryncrypto.WrapVEKForRecipient(newVEK, publicKey, secryncrypto.RecipientContext{VaultID: vaultID, RecipientID: recipient.ID, KeyVersion: targetVersion})
			if err != nil {
				return internalError("wrap rotated key for recipient failed", err)
			}
			envelopes = append(envelopes, recipientEnvelopeWrite(recipient.ID, *envelope))
		}
		if len(envelopes) == 0 {
			return internalError("vault has no active recipients", nil)
		}
		rotation, err := api.CreateRotation(a.context(), a.runtimeCfg.VaultID, client.RotationCreateRequest{RecipientEnvelopes: envelopes})
		if err != nil {
			return mapAPIError(err)
		}
		if rotation.FromKeyVersion != oldVersion || rotation.ToKeyVersion != targetVersion {
			return internalError("rotation response does not match the requested key versions", nil)
		}
		failure := func(err error) error {
			return pendingRotationError(rotation.ID, err)
		}
		staged := make([]client.RotationStageItem, 0)
		sourceCounts := map[string]int{"secret": 0, "secret_version": 0, "key": 0, "certificate": 0}
		for _, kind := range []string{"secret", "secret_version", "key", "certificate"} {
			sources, err := api.ListRotationSource(a.context(), a.runtimeCfg.VaultID, rotation.ID, kind)
			if err != nil {
				return failure(err)
			}
			for _, source := range sources {
				sourceCounts[kind]++
				if source.VaultID != vaultID || source.KeyVersion != oldVersion {
					return failure(fmt.Errorf("rotation source does not match the vault key context"))
				}
				if err := verifyRotationSourceDigest(source); err != nil {
					return failure(err)
				}
				resourceType, err := rotationResourceType(kind, source)
				if err != nil {
					return failure(err)
				}
				context := secryncrypto.ResourceContext{VaultID: source.VaultID, ResourceType: resourceType, ResourceID: source.ResourceID, AADVersion: source.AADVersion, KeyVersion: source.KeyVersion}
				envelope := secryncrypto.ResourceEnvelope{Version: source.Version, AADVersion: source.AADVersion, KeyVersion: source.KeyVersion, Nonce: source.Nonce, Ciphertext: source.Ciphertext, WrappedDEK: source.WrappedDEK}
				plaintext, err := secryncrypto.DecryptResource(envelope, oldVEK, context)
				if err != nil {
					return failure(err)
				}
				var payload struct {
					Name *string `json:"name"`
				}
				err = json.Unmarshal(plaintext, &payload)
				wipeBytes(plaintext)
				if err != nil || payload.Name == nil {
					return failure(fmt.Errorf("encrypted payload has no valid name"))
				}
				nameIndex, err := secryncrypto.NameIndexHex(newVEK, vaultID, *payload.Name)
				if err != nil {
					return failure(err)
				}
				wrappedDEK, err := secryncrypto.RewrapResourceDEK(envelope, oldVEK, newVEK, context, targetVersion)
				if err != nil {
					return failure(err)
				}
				staged = append(staged, client.RotationStageItem{Kind: kind, StorageID: source.StorageID, SourceDigest: source.SourceDigest, NameIndex: nameIndex, WrappedDEK: *wrappedDEK})
				if len(staged) == 100 {
					if err := api.StageRotationItems(a.context(), a.runtimeCfg.VaultID, rotation.ID, staged); err != nil {
						return failure(err)
					}
					staged = staged[:0]
				}
			}
		}
		if len(staged) > 0 {
			if err := api.StageRotationItems(a.context(), a.runtimeCfg.VaultID, rotation.ID, staged); err != nil {
				return failure(err)
			}
		}
		if sourceCounts["secret"] != rotation.ExpectedSecrets || sourceCounts["secret_version"] != rotation.ExpectedSecretVersions ||
			sourceCounts["key"] != rotation.ExpectedKeys || sourceCounts["certificate"] != rotation.ExpectedCertificates {
			return failure(fmt.Errorf("rotation source counts do not match the server snapshot"))
		}
		committed, err := api.CommitRotation(a.context(), a.runtimeCfg.VaultID, rotation.ID)
		if err != nil {
			return failure(err)
		}
		if committed.ID != rotation.ID || committed.FromKeyVersion != oldVersion || committed.ToKeyVersion != targetVersion || committed.Status != "committed" {
			return failure(fmt.Errorf("rotation commit response could not be verified"))
		}
		if a.flags.JSON {
			return output.JSON(a.stdout, committed)
		}
		_, _ = fmt.Fprintf(a.stdout, "Vault key rotated from version %d to %d\n", oldVersion, targetVersion)
		return nil
	}}
}

func verifyRotationSourceDigest(source client.RotationSourceItem) error {
	canonical := strings.Join([]string{
		"secryn-rotation-source-v1",
		source.Kind,
		source.StorageID,
		source.ResourceID,
		source.VaultID,
		source.NameIndex,
		strconv.Itoa(source.Version),
		strconv.Itoa(source.AADVersion),
		strconv.Itoa(source.KeyVersion),
		source.Nonce,
		source.Ciphertext,
		source.WrappedDEK.Nonce,
		source.WrappedDEK.Ciphertext,
	}, "\x00")
	expected := sha256.Sum256([]byte(canonical))
	received, err := hex.DecodeString(source.SourceDigest)
	if err != nil || len(received) != sha256.Size || subtle.ConstantTimeCompare(received, expected[:]) != 1 {
		return fmt.Errorf("rotation source digest does not match the encrypted source row")
	}
	return nil
}

func rotationResourceType(kind string, source client.RotationSourceItem) (string, error) {
	switch kind {
	case "secret_version":
		return "secret", nil
	case "secret", "key", "certificate":
		if source.ResourceID != source.StorageID {
			return "", fmt.Errorf("rotation %s source resource ID does not match its storage ID", kind)
		}
		return kind, nil
	default:
		return "", fmt.Errorf("unsupported rotation source kind")
	}
}

func (a *App) newE2EERotationCommand() *cobra.Command {
	rotation := &cobra.Command{Use: "rotation", Short: "Manage pending rotations"}
	rotation.AddCommand(&cobra.Command{Use: "cancel <rotation-id>", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		api, err := a.apiClient()
		if err != nil {
			return err
		}
		if _, err := a.canonicalLifecycleVault(api); err != nil {
			return mapAPIError(err)
		}
		if err := api.CancelRotation(a.context(), a.runtimeCfg.VaultID, args[0]); err != nil {
			return mapAPIError(err)
		}
		if a.flags.JSON {
			return output.JSON(a.stdout, map[string]any{"ok": true, "rotation_id": args[0]})
		}
		_, _ = fmt.Fprintf(a.stdout, "Rotation %s cancelled\n", args[0])
		return nil
	}})
	return rotation
}

func (a *App) unlockLifecycleVault(api *client.Client) ([]byte, string, int, func(), error) {
	cryptoContext, err := api.GetCryptoContext(a.context(), a.runtimeCfg.VaultID)
	if err != nil {
		return nil, "", 0, func() {}, err
	}
	if cryptoContext.EncryptionMode != "e2ee" || cryptoContext.KeyVersion == nil {
		return nil, "", 0, func() {}, fmt.Errorf("vault is not E2EE-enabled")
	}
	recipientIdentity, err := identity.Parse(a.runtimeCfg.RecipientID, a.runtimeCfg.RecipientPrivateKey)
	if err != nil {
		return nil, "", 0, func() {}, usageError("valid configured E2EE identity is required")
	}
	envelope, err := api.GetVaultKeyEnvelope(a.context(), a.runtimeCfg.VaultID, recipientIdentity.RecipientID())
	if err != nil {
		recipientIdentity.Destroy()
		return nil, "", 0, func() {}, err
	}
	privateKey := recipientIdentity.PrivateKey()
	recipientIdentity.Destroy()
	defer wipeBytes(privateKey)
	if envelope.VaultID != cryptoContext.VaultID || envelope.KeyVersion != *cryptoContext.KeyVersion {
		return nil, "", 0, func() {}, fmt.Errorf("vault key envelope does not match crypto context")
	}
	vek, err := secryncrypto.UnwrapVEKForRecipient(envelope.CryptoEnvelope(), privateKey, secryncrypto.RecipientContext{VaultID: envelope.VaultID, RecipientID: envelope.RecipientID, KeyVersion: envelope.KeyVersion})
	if err != nil {
		return nil, "", 0, func() {}, err
	}
	return vek, envelope.VaultID, envelope.KeyVersion, func() { wipeBytes(vek) }, nil
}

func (a *App) canonicalLifecycleVault(api *client.Client) (string, error) {
	cryptoContext, err := api.GetCryptoContext(a.context(), a.runtimeCfg.VaultID)
	if err != nil {
		return "", err
	}
	if cryptoContext.EncryptionMode != "e2ee" || cryptoContext.KeyVersion == nil {
		return "", fmt.Errorf("vault is not E2EE-enabled")
	}
	return cryptoContext.VaultID, nil
}

func (a *App) recoverPendingBootstrap(api *client.Client, cryptoContext client.CryptoContext, fileConfig config.Config) error {
	if cryptoContext.KeyVersion == nil || *cryptoContext.KeyVersion != 1 {
		return internalError("pending bootstrap cannot be reconciled with the server key version; the identity was retained", nil)
	}
	recipientIdentity, err := identity.Parse(fileConfig.RecipientID, fileConfig.RecipientPrivateKey)
	if err != nil {
		return usageError("pending bootstrap identity is malformed")
	}
	defer recipientIdentity.Destroy()
	envelope, err := api.GetVaultKeyEnvelope(a.context(), a.runtimeCfg.VaultID, recipientIdentity.RecipientID())
	if err != nil {
		return internalError("server is E2EE-enabled but the pending identity could not be verified; the identity was retained", err)
	}
	if envelope.VaultID != cryptoContext.VaultID || envelope.KeyVersion != *cryptoContext.KeyVersion {
		return internalError("server envelope does not match the pending bootstrap context; the identity was retained", nil)
	}
	privateKey := recipientIdentity.PrivateKey()
	defer wipeBytes(privateKey)
	vek, err := secryncrypto.UnwrapVEKForRecipient(envelope.CryptoEnvelope(), privateKey, secryncrypto.RecipientContext{
		VaultID: envelope.VaultID, RecipientID: envelope.RecipientID, KeyVersion: envelope.KeyVersion,
	})
	if err != nil {
		return internalError("server envelope cannot be decrypted by the pending identity; the identity was retained", err)
	}
	wipeBytes(vek)
	fileConfig.E2EEBootstrapPending = false
	if err := config.Save(a.cfgPath, fileConfig); err != nil {
		return internalError("bootstrap was verified but clearing pending state failed; rerun `secryn e2ee init`", err)
	}
	if a.flags.JSON {
		return output.JSON(a.stdout, map[string]any{"ok": true, "encryption_mode": "e2ee", "recipient_id": fileConfig.RecipientID, "recovered": true})
	}
	_, _ = fmt.Fprintf(a.stdout, "E2EE bootstrap recovered; recipient %s verified and saved securely in %s\n", fileConfig.RecipientID, a.cfgPath)
	return nil
}

func definitiveBootstrapRejection(err error) bool {
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusConflict, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

func (a *App) requireFileBackedLifecycleConfig(cmd *cobra.Command, requireIdentity bool) error {
	for _, name := range []string{"SECRYN_BASE_URL", "SECRYN_VAULT_ID", "SECRYN_ACCESS_KEY", "SECRYN_RECIPIENT_ID", "SECRYN_RECIPIENT_PRIVATE_KEY"} {
		if strings.TrimSpace(a.envLookup(name)) != "" {
			return usageError("E2EE lifecycle initialization requires unambiguous file-backed configuration; remove SECRYN_* overrides")
		}
	}
	if a.flagChanged(cmd, "base-url") || a.flagChanged(cmd, "vault-id") || a.flagChanged(cmd, "access-key") {
		return usageError("E2EE lifecycle initialization does not accept credential flags; save configuration first")
	}
	if _, err := os.Stat(a.cfgPath); err != nil {
		return usageError("E2EE lifecycle initialization requires an existing secure config file")
	}
	mode, err := a.runtimeCfg.EncryptionMode()
	if err != nil {
		return usageError(err.Error())
	}
	if requireIdentity && mode != "e2ee" {
		return usageError("configured E2EE identity is required")
	}
	if !requireIdentity && mode != "legacy" && mode != "e2ee_pending" {
		return usageError("vault already has a configured E2EE identity")
	}
	return nil
}

func provisionRequest(id, recipientType, label string, publicKey []byte, envelope secryncrypto.RecipientEnvelope) client.RecipientProvisionRequest {
	digest := sha256.Sum256(publicKey)
	return client.RecipientProvisionRequest{Recipient: client.RecipientWrite{ID: id, Type: recipientType, Label: label, PublicKey: lifecycleBase64URL.EncodeToString(publicKey), PublicKeyFingerprint: hex.EncodeToString(digest[:])}, Envelope: recipientEnvelopeWrite("", envelope)}
}

func recipientEnvelopeWrite(recipientID string, envelope secryncrypto.RecipientEnvelope) client.RecipientEnvelopeWrite {
	return client.RecipientEnvelopeWrite{RecipientID: recipientID, Version: envelope.Version, KeyVersion: envelope.KeyVersion, Algorithm: envelope.Algorithm, EphemeralPublicKey: envelope.EphemeralPublicKey, Nonce: envelope.Nonce, Ciphertext: envelope.Ciphertext}
}

func randomUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := cryptorand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func validLifecycleUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil && len(decoded) == 16
}

func pendingRotationError(rotationID string, cause error) error {
	return internalError(fmt.Sprintf("rotation %s remains pending; cancel with `secryn e2ee rotation cancel %s`", rotationID, rotationID), cause)
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}
