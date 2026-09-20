package client

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	secryncrypto "github.com/secryn/secryn-cli/internal/crypto"
)

type CryptoContext struct {
	Version           int    `json:"version"`
	VaultID           string `json:"vault_id"`
	EncryptionMode    string `json:"encryption_mode"`
	KeyVersion        *int   `json:"key_version"`
	BootstrapEligible bool   `json:"bootstrap_eligible"`
}

type Recipient struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	Label                string `json:"label"`
	PublicKey            string `json:"public_key"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	Status               string `json:"status"`
	CreatedAt            string `json:"created_at,omitempty"`
}

type RecipientWrite struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	Label                string `json:"label"`
	PublicKey            string `json:"public_key"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
}

type RecipientEnvelopeWrite struct {
	RecipientID        string `json:"recipient_id,omitempty"`
	Version            int    `json:"version"`
	KeyVersion         int    `json:"key_version"`
	Algorithm          string `json:"algorithm"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
}

type RecipientProvisionRequest struct {
	Recipient RecipientWrite         `json:"recipient"`
	Envelope  RecipientEnvelopeWrite `json:"envelope"`
}

type LifecycleResult struct {
	Version        int                     `json:"version"`
	VaultID        string                  `json:"vault_id,omitempty"`
	EncryptionMode string                  `json:"encryption_mode,omitempty"`
	KeyVersion     int                     `json:"key_version,omitempty"`
	Recipient      *Recipient              `json:"recipient,omitempty"`
	Envelope       *RecipientEnvelopeWrite `json:"envelope,omitempty"`
}

type Rotation struct {
	ID                     string  `json:"id"`
	FromKeyVersion         int     `json:"from_key_version"`
	ToKeyVersion           int     `json:"to_key_version"`
	Status                 string  `json:"status"`
	ExpectedSecrets        int     `json:"expected_secrets"`
	ExpectedSecretVersions int     `json:"expected_secret_versions"`
	ExpectedKeys           int     `json:"expected_keys"`
	ExpectedCertificates   int     `json:"expected_certificates"`
	Staged                 int     `json:"staged"`
	CommittedAt            *string `json:"committed_at"`
}

type RotationCreateRequest struct {
	RecipientEnvelopes []RecipientEnvelopeWrite `json:"recipient_envelopes"`
}

type RotationSourceItem struct {
	Kind         string                          `json:"kind"`
	StorageID    string                          `json:"storage_id"`
	ResourceID   string                          `json:"resource_id"`
	VaultID      string                          `json:"vault_id"`
	SourceDigest string                          `json:"source_digest"`
	NameIndex    string                          `json:"name_index"`
	Version      int                             `json:"version"`
	AADVersion   int                             `json:"aad_version"`
	KeyVersion   int                             `json:"key_version"`
	Nonce        string                          `json:"nonce"`
	Ciphertext   string                          `json:"ciphertext"`
	WrappedDEK   secryncrypto.WrappedKeyEnvelope `json:"wrapped_dek"`
}

type RotationStageItem struct {
	Kind         string                          `json:"kind"`
	StorageID    string                          `json:"storage_id"`
	SourceDigest string                          `json:"source_digest"`
	NameIndex    string                          `json:"name_index"`
	WrappedDEK   secryncrypto.WrappedKeyEnvelope `json:"wrapped_dek"`
}

func (c *Client) GetCryptoContext(ctx context.Context, vaultURI string) (CryptoContext, error) {
	payload, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/v2/vaults/%s/crypto/context", url.PathEscape(vaultURI)), nil)
	if err != nil {
		return CryptoContext{}, err
	}
	var result CryptoContext
	if err := json.Unmarshal(payload, &result); err != nil || result.Version != 1 || !validUUID(result.VaultID) ||
		(result.EncryptionMode != "legacy" && result.EncryptionMode != "e2ee") {
		return CryptoContext{}, fmt.Errorf("invalid crypto context response")
	}
	if (result.EncryptionMode == "legacy" && result.KeyVersion != nil) ||
		(result.EncryptionMode == "e2ee" && (result.KeyVersion == nil || *result.KeyVersion <= 0)) {
		return CryptoContext{}, fmt.Errorf("invalid crypto context response")
	}
	return result, nil
}

func (c *Client) BootstrapE2EE(ctx context.Context, vaultURI string, request RecipientProvisionRequest) (LifecycleResult, error) {
	return c.provisionRecipient(ctx, fmt.Sprintf("/v2/vaults/%s/crypto/bootstrap", url.PathEscape(vaultURI)), request)
}

func (c *Client) ListRecipients(ctx context.Context, vaultURI string) ([]Recipient, error) {
	payload, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/v2/vaults/%s/crypto/recipients", url.PathEscape(vaultURI)), nil)
	if err != nil {
		return nil, err
	}
	items, err := decodeV2List[Recipient](payload)
	if err != nil {
		return nil, fmt.Errorf("decode recipients: %w", err)
	}
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		publicKey, err := strictBase64URL.DecodeString(item.PublicKey)
		fingerprint := sha256.Sum256(publicKey)
		if !validUUID(item.ID) || err != nil || len(publicKey) != 32 || item.PublicKeyFingerprint != fmt.Sprintf("%x", fingerprint) ||
			(item.Status != "active" && item.Status != "revoked") {
			return nil, fmt.Errorf("invalid recipient response")
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return nil, fmt.Errorf("recipient response repeated an ID")
		}
		seen[item.ID] = struct{}{}
	}
	return items, nil
}

func (c *Client) AddRecipient(ctx context.Context, vaultURI string, request RecipientProvisionRequest) (LifecycleResult, error) {
	return c.provisionRecipient(ctx, fmt.Sprintf("/v2/vaults/%s/crypto/recipients", url.PathEscape(vaultURI)), request)
}

func (c *Client) RevokeRecipient(ctx context.Context, vaultURI, recipientID string) error {
	if !validUUID(recipientID) {
		return fmt.Errorf("valid recipient UUID is required")
	}
	_, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/v2/vaults/%s/crypto/recipients/%s", url.PathEscape(vaultURI), recipientID), nil)
	return err
}

func (c *Client) CreateRotation(ctx context.Context, vaultURI string, request RotationCreateRequest) (Rotation, error) {
	if len(request.RecipientEnvelopes) == 0 || len(request.RecipientEnvelopes) > 1000 {
		return Rotation{}, fmt.Errorf("invalid rotation request")
	}
	seen := make(map[string]struct{}, len(request.RecipientEnvelopes))
	targetKeyVersion := request.RecipientEnvelopes[0].KeyVersion
	for _, envelope := range request.RecipientEnvelopes {
		if !validUUID(envelope.RecipientID) || envelope.Version != 1 || envelope.KeyVersion <= 1 || envelope.KeyVersion != targetKeyVersion ||
			envelope.Algorithm != secryncrypto.RecipientWrapAlgorithm || !validEncodedLength(envelope.EphemeralPublicKey, 32) ||
			!validEncodedLength(envelope.Nonce, 24) || !validEncodedLength(envelope.Ciphertext, 48) {
			return Rotation{}, fmt.Errorf("invalid rotation request")
		}
		if _, duplicate := seen[envelope.RecipientID]; duplicate {
			return Rotation{}, fmt.Errorf("rotation request repeated a recipient")
		}
		seen[envelope.RecipientID] = struct{}{}
	}
	result, err := c.rotationAction(ctx, http.MethodPost, fmt.Sprintf("/v2/vaults/%s/crypto/rotations", url.PathEscape(vaultURI)), request)
	if err == nil && (result.Status != "pending" || result.Staged != 0 || result.ToKeyVersion != targetKeyVersion) {
		return Rotation{}, fmt.Errorf("invalid rotation start response")
	}
	return result, err
}

func (c *Client) ListRotationSource(ctx context.Context, vaultURI, rotationID, kind string) ([]RotationSourceItem, error) {
	if !validUUID(rotationID) || (kind != "secret" && kind != "secret_version" && kind != "key" && kind != "certificate") {
		return nil, fmt.Errorf("invalid rotation source request")
	}
	items := make([]RotationSourceItem, 0)
	cursor := ""
	seen := make(map[string]struct{})
	seenCursors := make(map[string]struct{})
	lastStorageID := ""
	for page := 0; page < maximumEncryptedPages; page++ {
		query := url.Values{"kind": []string{kind}, "limit": []string{"5"}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		endpoint := fmt.Sprintf("/v2/vaults/%s/crypto/rotations/%s/source?%s", url.PathEscape(vaultURI), rotationID, query.Encode())
		payload, err := c.do(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		pageItems, next, err := decodeV2Page[RotationSourceItem](payload)
		if err != nil || len(pageItems) > 5 || len(items)+len(pageItems) > maximumEncryptedSecrets {
			return nil, fmt.Errorf("invalid rotation source page")
		}
		for _, item := range pageItems {
			if item.Kind != kind || !validUUID(item.StorageID) || !validUUID(item.ResourceID) || !validUUID(item.VaultID) || !validNameIndex(item.SourceDigest) ||
				validateEncryptedFields(item.NameIndex, item.Version, item.AADVersion, item.KeyVersion, item.Nonce, item.Ciphertext, item.WrappedDEK) != nil {
				return nil, fmt.Errorf("invalid rotation source item")
			}
			if _, duplicate := seen[item.StorageID]; duplicate {
				return nil, fmt.Errorf("rotation source repeated an item")
			}
			if lastStorageID != "" && item.StorageID <= lastStorageID {
				return nil, fmt.Errorf("rotation source is out of order")
			}
			seen[item.StorageID] = struct{}{}
			items = append(items, item)
			lastStorageID = item.StorageID
		}
		if next == nil {
			return items, nil
		}
		cursor = *next
		if !validUUID(cursor) || len(pageItems) == 0 || cursor != pageItems[len(pageItems)-1].StorageID {
			return nil, fmt.Errorf("invalid rotation source cursor")
		}
		if _, duplicate := seenCursors[cursor]; duplicate {
			return nil, fmt.Errorf("rotation source cursor loop")
		}
		seenCursors[cursor] = struct{}{}
	}
	return nil, fmt.Errorf("rotation source page limit exceeded")
}

func (c *Client) StageRotationItems(ctx context.Context, vaultURI, rotationID string, items []RotationStageItem) error {
	if !validUUID(rotationID) || len(items) == 0 || len(items) > 100 {
		return fmt.Errorf("invalid rotation stage request")
	}
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		key := item.Kind + "\x00" + item.StorageID
		if (item.Kind != "secret" && item.Kind != "secret_version" && item.Kind != "key" && item.Kind != "certificate") || !validUUID(item.StorageID) ||
			!validNameIndex(item.SourceDigest) || !validNameIndex(item.NameIndex) ||
			!validEncodedLength(item.WrappedDEK.Nonce, 24) || !validEncodedLength(item.WrappedDEK.Ciphertext, 48) {
			return fmt.Errorf("invalid rotation stage request")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("rotation stage request repeated an item")
		}
		seen[key] = struct{}{}
	}
	body, err := json.Marshal(map[string]any{"items": items})
	if err != nil {
		return err
	}
	payload, err := c.do(ctx, http.MethodPut, fmt.Sprintf("/v2/vaults/%s/crypto/rotations/%s/items", url.PathEscape(vaultURI), rotationID), body)
	if err != nil {
		return err
	}
	var result struct {
		Version int `json:"version"`
		Staged  int `json:"staged"`
	}
	if err := json.Unmarshal(payload, &result); err != nil || result.Version != 1 || result.Staged < len(items) {
		return fmt.Errorf("invalid rotation stage response")
	}
	return nil
}

func (c *Client) CommitRotation(ctx context.Context, vaultURI, rotationID string) (Rotation, error) {
	if !validUUID(rotationID) {
		return Rotation{}, fmt.Errorf("valid rotation UUID is required")
	}
	result, err := c.rotationAction(ctx, http.MethodPost, fmt.Sprintf("/v2/vaults/%s/crypto/rotations/%s/commit", url.PathEscape(vaultURI), rotationID), nil)
	if err == nil && result.ID != rotationID {
		return Rotation{}, fmt.Errorf("rotation commit response does not match requested ID")
	}
	if err == nil && result.Status != "committed" {
		return Rotation{}, fmt.Errorf("invalid rotation commit response")
	}
	return result, err
}

func (c *Client) CancelRotation(ctx context.Context, vaultURI, rotationID string) error {
	if !validUUID(rotationID) {
		return fmt.Errorf("valid rotation UUID is required")
	}
	_, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/v2/vaults/%s/crypto/rotations/%s", url.PathEscape(vaultURI), rotationID), nil)
	return err
}

func (c *Client) provisionRecipient(ctx context.Context, endpoint string, request RecipientProvisionRequest) (LifecycleResult, error) {
	if err := validateRecipientProvisionRequest(request); err != nil {
		return LifecycleResult{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return LifecycleResult{}, err
	}
	payload, err := c.do(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return LifecycleResult{}, err
	}
	var result LifecycleResult
	if err := json.Unmarshal(payload, &result); err != nil || result.Version != 1 {
		return LifecycleResult{}, fmt.Errorf("invalid recipient lifecycle response")
	}
	if result.Recipient == nil || result.Envelope == nil || result.Recipient.ID != request.Recipient.ID ||
		result.Recipient.Type != request.Recipient.Type || result.Recipient.Label != request.Recipient.Label ||
		result.Recipient.Status != "active" ||
		result.Recipient.PublicKey != request.Recipient.PublicKey || result.Recipient.PublicKeyFingerprint != request.Recipient.PublicKeyFingerprint ||
		result.Envelope.Version != request.Envelope.Version || result.Envelope.KeyVersion != request.Envelope.KeyVersion ||
		result.Envelope.Algorithm != request.Envelope.Algorithm || result.Envelope.EphemeralPublicKey != request.Envelope.EphemeralPublicKey ||
		result.Envelope.Nonce != request.Envelope.Nonce || result.Envelope.Ciphertext != request.Envelope.Ciphertext {
		return LifecycleResult{}, fmt.Errorf("recipient lifecycle response does not match request")
	}
	return result, nil
}

func validateRecipientProvisionRequest(request RecipientProvisionRequest) error {
	publicKey, publicKeyErr := strictBase64URL.DecodeString(request.Recipient.PublicKey)
	fingerprint := sha256.Sum256(publicKey)
	if !validUUID(request.Recipient.ID) ||
		(request.Recipient.Type != "cli" && request.Recipient.Type != "service" && request.Recipient.Type != "browser") ||
		request.Recipient.Label == "" || len(request.Recipient.Label) > 255 || publicKeyErr != nil || len(publicKey) != 32 ||
		request.Recipient.PublicKeyFingerprint != fmt.Sprintf("%x", fingerprint) ||
		request.Envelope.Version != 1 || request.Envelope.KeyVersion <= 0 || request.Envelope.Algorithm != secryncrypto.RecipientWrapAlgorithm ||
		!validEncodedLength(request.Envelope.EphemeralPublicKey, 32) || !validEncodedLength(request.Envelope.Nonce, 24) ||
		!validEncodedLength(request.Envelope.Ciphertext, 48) {
		return fmt.Errorf("invalid recipient lifecycle request")
	}
	return nil
}

func (c *Client) rotationAction(ctx context.Context, method, endpoint string, request any) (Rotation, error) {
	var body []byte
	var err error
	if request != nil {
		body, err = json.Marshal(request)
		if err != nil {
			return Rotation{}, err
		}
	}
	payload, err := c.do(ctx, method, endpoint, body)
	if err != nil {
		return Rotation{}, err
	}
	result, err := decodeV2One[Rotation](payload)
	if err != nil || !validUUID(result.ID) || result.FromKeyVersion <= 0 || result.ToKeyVersion != result.FromKeyVersion+1 ||
		(result.Status != "pending" && result.Status != "committed") || result.ExpectedSecrets < 0 || result.ExpectedSecretVersions < 0 ||
		result.ExpectedKeys < 0 || result.ExpectedCertificates < 0 || result.Staged < 0 {
		return Rotation{}, fmt.Errorf("invalid rotation response")
	}
	return result, nil
}

func decodeV2List[T any](payload []byte) ([]T, error) {
	var wrapped struct {
		Version int `json:"version"`
		Data    []T `json:"data"`
	}
	if err := json.Unmarshal(payload, &wrapped); err != nil || wrapped.Version != 1 || wrapped.Data == nil {
		return nil, fmt.Errorf("unsupported or malformed API v2 response")
	}
	return wrapped.Data, nil
}
