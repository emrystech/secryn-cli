package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// EncryptedResource is the common opaque v2 envelope used for keys and
// certificates. Plaintext resource metadata and material are never present.
type EncryptedResource = EncryptedSecret

func (c *Client) ListEncryptedResources(ctx context.Context, vaultURI, resourceType string) ([]EncryptedResource, error) {
	path, kind, err := encryptedResourcePath(resourceType)
	if err != nil {
		return nil, err
	}
	items := make([]EncryptedResource, 0)
	seenIDs := make(map[string]struct{})
	seenCursors := make(map[string]struct{})
	cursor := ""
	lastID := ""
	for page := 0; page < maximumEncryptedPages; page++ {
		query := url.Values{"limit": []string{"5"}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		payload, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/v2/vaults/%s/%s?%s", url.PathEscape(vaultURI), path, query.Encode()), nil)
		if err != nil {
			return nil, err
		}
		pageItems, next, err := decodeEncryptedResourcePage(payload, kind)
		if err != nil || len(pageItems) > encryptedSecretsPageLimit || len(items)+len(pageItems) > maximumEncryptedSecrets {
			return nil, fmt.Errorf("invalid encrypted %s page", kind)
		}
		for _, item := range pageItems {
			if err := validateEncryptedSecret(item); err != nil {
				return nil, err
			}
			if _, duplicate := seenIDs[item.ID]; duplicate || (lastID != "" && item.ID <= lastID) {
				return nil, fmt.Errorf("encrypted %s pagination repeated or reordered a resource", kind)
			}
			seenIDs[item.ID] = struct{}{}
			lastID = item.ID
			items = append(items, item)
		}
		if next == nil {
			return items, nil
		}
		cursor = *next
		if !validUUID(cursor) || len(pageItems) == 0 || cursor != pageItems[len(pageItems)-1].ID {
			return nil, fmt.Errorf("invalid encrypted %s cursor", kind)
		}
		if _, duplicate := seenCursors[cursor]; duplicate {
			return nil, fmt.Errorf("encrypted %s cursor loop", kind)
		}
		seenCursors[cursor] = struct{}{}
	}
	return nil, fmt.Errorf("encrypted %s page limit exceeded", kind)
}

func (c *Client) GetEncryptedResourceByIndex(ctx context.Context, vaultURI, resourceType, nameIndex string) (EncryptedResource, error) {
	path, kind, err := encryptedResourcePath(resourceType)
	if err != nil || !validNameIndex(nameIndex) {
		return EncryptedResource{}, fmt.Errorf("invalid encrypted resource request")
	}
	item, err := c.getEncryptedResource(ctx, fmt.Sprintf("/v2/vaults/%s/%s/by-index/%s", url.PathEscape(vaultURI), path, nameIndex), kind)
	if err == nil && item.NameIndex != nameIndex {
		return EncryptedResource{}, fmt.Errorf("encrypted %s response does not match requested name index", kind)
	}
	return item, err
}

func (c *Client) GetEncryptedResource(ctx context.Context, vaultURI, resourceType, resourceID string) (EncryptedResource, error) {
	path, kind, err := encryptedResourcePath(resourceType)
	if err != nil || !validUUID(resourceID) {
		return EncryptedResource{}, fmt.Errorf("invalid encrypted resource request")
	}
	item, err := c.getEncryptedResource(ctx, fmt.Sprintf("/v2/vaults/%s/%s/%s", url.PathEscape(vaultURI), path, resourceID), kind)
	if err == nil && item.ID != resourceID {
		return EncryptedResource{}, fmt.Errorf("encrypted %s response does not match requested ID", kind)
	}
	return item, err
}

func (c *Client) getEncryptedResource(ctx context.Context, endpoint, kind string) (EncryptedResource, error) {
	payload, err := c.do(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return EncryptedResource{}, err
	}
	var wrapped struct {
		Version      int               `json:"version"`
		ResourceType string            `json:"resource_type"`
		Data         EncryptedResource `json:"data"`
	}
	if err := json.Unmarshal(payload, &wrapped); err != nil || wrapped.Version != 1 || wrapped.ResourceType != kind {
		return EncryptedResource{}, fmt.Errorf("invalid encrypted %s response", kind)
	}
	if err := validateEncryptedSecret(wrapped.Data); err != nil {
		return EncryptedResource{}, err
	}
	return wrapped.Data, nil
}

func decodeEncryptedResourcePage(payload []byte, kind string) ([]EncryptedResource, *string, error) {
	var wrapped struct {
		Version      int                 `json:"version"`
		ResourceType string              `json:"resource_type"`
		Data         []EncryptedResource `json:"data"`
		Meta         json.RawMessage     `json:"meta"`
	}
	if err := json.Unmarshal(payload, &wrapped); err != nil || wrapped.Version != 1 || wrapped.ResourceType != kind || wrapped.Data == nil {
		return nil, nil, fmt.Errorf("invalid encrypted %s response", kind)
	}
	pagePayload, err := json.Marshal(map[string]any{"version": wrapped.Version, "data": wrapped.Data, "meta": wrapped.Meta})
	if err != nil {
		return nil, nil, err
	}
	return decodeV2Page[EncryptedResource](pagePayload)
}

func encryptedResourcePath(resourceType string) (string, string, error) {
	switch resourceType {
	case "key":
		return "keys", "key", nil
	case "certificate":
		return "certificates", "certificate", nil
	default:
		return "", "", fmt.Errorf("unsupported encrypted resource type")
	}
}
