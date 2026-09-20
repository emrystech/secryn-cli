package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"

	secryncrypto "github.com/secryn/secryn-cli/internal/crypto"
)

const apiV2Version = 1

const (
	encryptedSecretsPageLimit = 5
	maximumEncryptedSecrets   = 10_000
	maximumEncryptedPages     = maximumEncryptedSecrets / encryptedSecretsPageLimit
)

var strictBase64URL = base64.RawURLEncoding.Strict()

func (c *Client) GetVaultKeyEnvelope(ctx context.Context, vaultID, recipientID string) (VaultKeyEnvelope, error) {
	if !validUUID(recipientID) {
		return VaultKeyEnvelope{}, fmt.Errorf("recipient ID is required")
	}
	headers := make(http.Header)
	headers.Set("X-Secryn-Recipient-ID", recipientID)
	payload, err := c.doWithHeaders(ctx, http.MethodGet, fmt.Sprintf("/v2/vaults/%s/crypto/envelope", url.PathEscape(vaultID)), headers, nil)
	if err != nil {
		return VaultKeyEnvelope{}, err
	}
	var envelope VaultKeyEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return VaultKeyEnvelope{}, fmt.Errorf("decode vault key envelope: %w", err)
	}
	if err := validateVaultKeyEnvelope(envelope, recipientID); err != nil {
		return VaultKeyEnvelope{}, err
	}
	return envelope, nil
}

func (c *Client) ListEncryptedSecrets(ctx context.Context, vaultID string) ([]EncryptedSecret, error) {
	items := make([]EncryptedSecret, 0)
	seenCursors := make(map[string]struct{})
	seenIDs := make(map[string]struct{})
	nextCursor := ""
	lastID := ""
	for pageNumber := 0; pageNumber < maximumEncryptedPages; pageNumber++ {
		query := url.Values{"limit": []string{fmt.Sprintf("%d", encryptedSecretsPageLimit)}}
		if nextCursor != "" {
			query.Set("cursor", nextCursor)
		}
		endpoint := fmt.Sprintf("/v2/vaults/%s/secrets?%s", url.PathEscape(vaultID), query.Encode())
		payload, err := c.do(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		page, cursor, err := decodeV2Page[EncryptedSecret](payload)
		if err != nil {
			return nil, fmt.Errorf("decode encrypted secrets list: %w", err)
		}
		if len(page) > encryptedSecretsPageLimit || len(items)+len(page) > maximumEncryptedSecrets {
			return nil, fmt.Errorf("encrypted secrets pagination limit exceeded")
		}
		for _, item := range page {
			if err := validateEncryptedSecret(item); err != nil {
				return nil, err
			}
			if _, duplicate := seenIDs[item.ID]; duplicate {
				return nil, fmt.Errorf("encrypted secrets pagination repeated a resource")
			}
			if lastID != "" && item.ID <= lastID {
				return nil, fmt.Errorf("encrypted secrets pagination is out of order")
			}
			seenIDs[item.ID] = struct{}{}
			items = append(items, item)
			lastID = item.ID
		}
		if cursor == nil {
			return items, nil
		}
		nextCursor = *cursor
		if !validCursor(nextCursor) || len(page) == 0 || nextCursor != page[len(page)-1].ID {
			return nil, fmt.Errorf("invalid encrypted secrets cursor")
		}
		if _, duplicate := seenCursors[nextCursor]; duplicate {
			return nil, fmt.Errorf("encrypted secrets pagination cursor loop")
		}
		seenCursors[nextCursor] = struct{}{}
	}
	return nil, fmt.Errorf("encrypted secrets pagination page limit exceeded")
}

func (c *Client) GetEncryptedSecretByIndex(ctx context.Context, vaultID, nameIndex string) (EncryptedSecret, error) {
	if !validNameIndex(nameIndex) {
		return EncryptedSecret{}, fmt.Errorf("invalid name index")
	}
	item, err := c.getEncryptedSecret(ctx, fmt.Sprintf("/v2/vaults/%s/secrets/by-index/%s", url.PathEscape(vaultID), nameIndex))
	if err != nil {
		return EncryptedSecret{}, err
	}
	if item.NameIndex != nameIndex {
		return EncryptedSecret{}, fmt.Errorf("encrypted secret response does not match requested name index")
	}
	return item, nil
}

func (c *Client) GetEncryptedSecret(ctx context.Context, vaultID, secretID string) (EncryptedSecret, error) {
	if !validUUID(secretID) {
		return EncryptedSecret{}, fmt.Errorf("valid secret UUID is required")
	}
	item, err := c.getEncryptedSecret(ctx, fmt.Sprintf("/v2/vaults/%s/secrets/%s", url.PathEscape(vaultID), url.PathEscape(secretID)))
	if err != nil {
		return EncryptedSecret{}, err
	}
	if item.ID != secretID {
		return EncryptedSecret{}, fmt.Errorf("encrypted secret response does not match requested ID")
	}
	return item, nil
}

func (c *Client) CreateEncryptedSecret(ctx context.Context, vaultID string, input EncryptedSecretWrite) (EncryptedSecret, error) {
	if !validUUID(input.ID) {
		return EncryptedSecret{}, fmt.Errorf("valid secret UUID is required")
	}
	item, err := c.writeEncryptedSecret(ctx, http.MethodPost, fmt.Sprintf("/v2/vaults/%s/secrets", url.PathEscape(vaultID)), input)
	if err != nil {
		return EncryptedSecret{}, err
	}
	if item.ID != input.ID || !matchesEncryptedWrite(item, input) {
		return EncryptedSecret{}, fmt.Errorf("encrypted secret create response does not match request")
	}
	return item, nil
}

func (c *Client) UpdateEncryptedSecret(ctx context.Context, vaultID, secretID string, input EncryptedSecretWrite) (EncryptedSecret, error) {
	return c.updateEncryptedSecret(ctx, http.MethodPut, vaultID, secretID, input)
}

func (c *Client) PatchEncryptedSecret(ctx context.Context, vaultID, secretID string, input EncryptedSecretWrite) (EncryptedSecret, error) {
	return c.updateEncryptedSecret(ctx, http.MethodPatch, vaultID, secretID, input)
}

func (c *Client) DeleteEncryptedSecret(ctx context.Context, vaultID, secretID string) error {
	if !validUUID(secretID) {
		return fmt.Errorf("valid secret UUID is required")
	}
	_, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/v2/vaults/%s/secrets/%s", url.PathEscape(vaultID), url.PathEscape(secretID)), nil)
	return err
}

func (c *Client) updateEncryptedSecret(ctx context.Context, method, vaultID, secretID string, input EncryptedSecretWrite) (EncryptedSecret, error) {
	if !validUUID(secretID) {
		return EncryptedSecret{}, fmt.Errorf("valid secret UUID is required")
	}
	item, err := c.writeEncryptedSecret(ctx, method, fmt.Sprintf("/v2/vaults/%s/secrets/%s", url.PathEscape(vaultID), url.PathEscape(secretID)), input)
	if err != nil {
		return EncryptedSecret{}, err
	}
	if item.ID != secretID || !matchesEncryptedWrite(item, input) {
		return EncryptedSecret{}, fmt.Errorf("encrypted secret update response does not match request")
	}
	return item, nil
}

func (c *Client) getEncryptedSecret(ctx context.Context, endpoint string) (EncryptedSecret, error) {
	payload, err := c.do(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return EncryptedSecret{}, err
	}
	item, err := decodeV2One[EncryptedSecret](payload)
	if err != nil {
		return EncryptedSecret{}, fmt.Errorf("decode encrypted secret: %w", err)
	}
	if err := validateEncryptedSecret(item); err != nil {
		return EncryptedSecret{}, err
	}
	return item, nil
}

func (c *Client) writeEncryptedSecret(ctx context.Context, method, endpoint string, input EncryptedSecretWrite) (EncryptedSecret, error) {
	if err := validateEncryptedSecretWrite(input); err != nil {
		return EncryptedSecret{}, err
	}
	body, err := json.Marshal(input)
	if err != nil {
		return EncryptedSecret{}, fmt.Errorf("encode encrypted secret: %w", err)
	}
	payload, err := c.do(ctx, method, endpoint, body)
	if err != nil {
		return EncryptedSecret{}, err
	}
	item, err := decodeV2One[EncryptedSecret](payload)
	if err != nil {
		return EncryptedSecret{}, fmt.Errorf("decode encrypted secret: %w", err)
	}
	if err := validateEncryptedSecret(item); err != nil {
		return EncryptedSecret{}, err
	}
	return item, nil
}

func validateVaultKeyEnvelope(envelope VaultKeyEnvelope, requestedRecipientID string) error {
	if envelope.Version != apiV2Version || envelope.KeyVersion <= 0 || !validUUID(envelope.VaultID) ||
		!validUUID(envelope.RecipientID) || envelope.RecipientID != requestedRecipientID || envelope.Algorithm == "" {
		return fmt.Errorf("invalid vault key envelope")
	}
	if !validEncodedLength(envelope.EphemeralPublicKey, 32) || !validEncodedLength(envelope.Nonce, 24) ||
		!validEncodedLength(envelope.Ciphertext, 48) {
		return fmt.Errorf("invalid vault key envelope")
	}
	return nil
}

func validateEncryptedSecret(item EncryptedSecret) error {
	if !validUUID(item.ID) || !validUUID(item.VaultID) {
		return fmt.Errorf("invalid encrypted secret envelope")
	}
	return validateEncryptedFields(
		item.NameIndex, item.Version, item.AADVersion, item.KeyVersion, item.Nonce,
		item.Ciphertext, item.WrappedDEK,
	)
}

func validateEncryptedSecretWrite(input EncryptedSecretWrite) error {
	return validateEncryptedFields(
		input.NameIndex, input.Version, input.AADVersion, input.KeyVersion, input.Nonce,
		input.Ciphertext, input.WrappedDEK,
	)
}

func validateEncryptedFields(
	nameIndex string,
	version, aadVersion, keyVersion int,
	nonce, ciphertext string,
	wrappedDEK secryncrypto.WrappedKeyEnvelope,
) error {
	if !validNameIndex(nameIndex) || version != apiV2Version || aadVersion != apiV2Version || keyVersion <= 0 ||
		!validEncodedLength(nonce, 24) || !validCiphertext(ciphertext) || !validEncodedLength(wrappedDEK.Nonce, 24) ||
		!validEncodedLength(wrappedDEK.Ciphertext, 48) {
		return fmt.Errorf("invalid encrypted secret envelope")
	}
	return nil
}

func validNameIndex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

func validCursor(value string) bool {
	return validUUID(value)
}

func matchesEncryptedWrite(item EncryptedSecret, input EncryptedSecretWrite) bool {
	return item.NameIndex == input.NameIndex && item.Version == input.Version &&
		item.AADVersion == input.AADVersion && item.KeyVersion == input.KeyVersion &&
		item.Nonce == input.Nonce && item.Ciphertext == input.Ciphertext &&
		reflect.DeepEqual(item.WrappedDEK, input.WrappedDEK)
}

func validEncodedLength(value string, expected int) bool {
	decoded, err := strictBase64URL.DecodeString(value)
	return err == nil && len(decoded) == expected
}

func validCiphertext(value string) bool {
	decoded, err := strictBase64URL.DecodeString(value)
	return err == nil && len(decoded) >= 16
}

func decodeV2Page[T any](payload []byte) ([]T, *string, error) {
	var wrapped struct {
		Version int             `json:"version"`
		Data    []T             `json:"data"`
		Meta    json.RawMessage `json:"meta"`
	}
	if err := json.Unmarshal(payload, &wrapped); err != nil {
		return nil, nil, err
	}
	if wrapped.Version != apiV2Version || wrapped.Data == nil || len(wrapped.Meta) == 0 {
		return nil, nil, fmt.Errorf("unsupported or malformed API v2 response")
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(wrapped.Meta, &meta); err != nil {
		return nil, nil, fmt.Errorf("malformed API v2 pagination metadata")
	}
	rawCursor, exists := meta["next_cursor"]
	if !exists {
		return nil, nil, fmt.Errorf("missing API v2 next cursor")
	}
	if string(rawCursor) == "null" {
		return wrapped.Data, nil, nil
	}
	var cursor string
	if err := json.Unmarshal(rawCursor, &cursor); err != nil || cursor == "" {
		return nil, nil, fmt.Errorf("invalid API v2 next cursor")
	}
	return wrapped.Data, &cursor, nil
}

func decodeV2One[T any](payload []byte) (T, error) {
	var zero T
	var wrapped struct {
		Version int             `json:"version"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(payload, &wrapped); err != nil {
		return zero, err
	}
	if wrapped.Version != apiV2Version || len(wrapped.Data) == 0 || string(wrapped.Data) == "null" {
		return zero, fmt.Errorf("unsupported or malformed API v2 response")
	}
	var item T
	if err := json.Unmarshal(wrapped.Data, &item); err != nil {
		return zero, err
	}
	return item, nil
}
