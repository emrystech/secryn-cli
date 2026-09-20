package secrets

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"unicode/utf8"

	"github.com/secryn/secryn-cli/internal/client"
	secryncrypto "github.com/secryn/secryn-cli/internal/crypto"
	"github.com/secryn/secryn-cli/internal/identity"
)

const maxDecryptedSecretPayload = 1024 * 1024

var (
	ErrInvalidPayload   = errors.New("invalid encrypted secret payload")
	ErrEnvelopeMismatch = errors.New("encrypted secret envelope does not match vault key")
)

type E2EEService struct {
	client   *client.Client
	identity *identity.Identity
}

type decryptedPayload struct {
	Name        *string  `json:"name"`
	Value       *string  `json:"value"`
	ContentType string   `json:"contentType,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type DecryptedResource struct {
	ID             string       `json:"id"`
	Name           string       `json:"name"`
	UpdatedAt      string       `json:"updated_at,omitempty"`
	KeyType        string       `json:"keyType,omitempty"`
	KeySize        int          `json:"keySize,omitempty"`
	KeyCurve       string       `json:"keyCurve,omitempty"`
	OutputFormat   string       `json:"outputFormat,omitempty"`
	Material       *KeyMaterial `json:"material,omitempty"`
	CertificatePEM string       `json:"certificatePem,omitempty"`
	PrivateKeyPEM  string       `json:"privateKeyPem,omitempty"`
	Tags           []string     `json:"tags,omitempty"`
}

type KeyMaterial struct {
	PEMPrivate     string `json:"pemPrivate,omitempty"`
	OpenSSHPrivate string `json:"openSshPrivate,omitempty"`
	PEMPublic      string `json:"pemPublic,omitempty"`
	OpenSSHPublic  string `json:"openSshPublic,omitempty"`
}

func (m *KeyMaterial) Select(format string, includePrivate bool) (string, error) {
	if m == nil {
		return "", ErrInvalidPayload
	}
	switch format {
	case "pem":
		if includePrivate && m.PEMPrivate != "" {
			return m.PEMPrivate, nil
		}
		if m.PEMPublic != "" {
			return m.PEMPublic, nil
		}
	case "ssh":
		if includePrivate && m.OpenSSHPrivate != "" {
			return m.OpenSSHPrivate, nil
		}
		if m.OpenSSHPublic != "" {
			return m.OpenSSHPublic, nil
		}
	default:
		return "", fmt.Errorf("unsupported key format")
	}
	return "", fmt.Errorf("requested key material is unavailable")
}

type keyPayload struct {
	Name         *string      `json:"name"`
	Material     *KeyMaterial `json:"material"`
	KeyType      string       `json:"keyType,omitempty"`
	KeySize      *int         `json:"keySize,omitempty"`
	KeyCurve     string       `json:"keyCurve,omitempty"`
	OutputFormat string       `json:"outputFormat,omitempty"`
	Tags         []string     `json:"tags,omitempty"`
}

type certificatePayload struct {
	Name           *string  `json:"name"`
	CertificatePEM *string  `json:"certificatePem"`
	PrivateKeyPEM  *string  `json:"privateKeyPem,omitempty"`
	Tags           []string `json:"tags,omitempty"`
}

type unlockedVault struct {
	id         string
	keyVersion int
	vek        []byte
}

func NewE2EE(apiClient *client.Client, recipientIdentity *identity.Identity) (*E2EEService, error) {
	if apiClient == nil || recipientIdentity == nil || recipientIdentity.RecipientID() == "" {
		return nil, fmt.Errorf("E2EE client and recipient identity are required")
	}
	return &E2EEService{client: apiClient, identity: recipientIdentity}, nil
}

func (s *E2EEService) Test(ctx context.Context, vaultURI string) error {
	unlocked, err := s.unlock(ctx, vaultURI)
	if err != nil {
		return err
	}
	unlocked.destroy()
	return nil
}

func (s *E2EEService) List(ctx context.Context, vaultURI string) ([]client.Secret, error) {
	unlocked, err := s.unlock(ctx, vaultURI)
	if err != nil {
		return nil, err
	}
	defer unlocked.destroy()

	encrypted, err := s.client.ListEncryptedSecrets(ctx, vaultURI)
	if err != nil {
		return nil, err
	}
	result := make([]client.Secret, 0, len(encrypted))
	for _, item := range encrypted {
		secret, err := decryptSecret(item, unlocked)
		if err != nil {
			return nil, err
		}
		result = append(result, secret)
	}
	return result, nil
}

func (s *E2EEService) Get(ctx context.Context, vaultURI, name string) (client.Secret, error) {
	unlocked, err := s.unlock(ctx, vaultURI)
	if err != nil {
		return client.Secret{}, err
	}
	defer unlocked.destroy()

	nameIndex, err := secryncrypto.NameIndexHex(unlocked.vek, unlocked.id, name)
	if err != nil {
		return client.Secret{}, err
	}
	encrypted, err := s.client.GetEncryptedSecretByIndex(ctx, vaultURI, nameIndex)
	if err != nil {
		return client.Secret{}, err
	}
	return decryptSecret(encrypted, unlocked)
}

func (s *E2EEService) ListResources(ctx context.Context, vaultURI, resourceType string) ([]DecryptedResource, error) {
	unlocked, err := s.unlock(ctx, vaultURI)
	if err != nil {
		return nil, err
	}
	defer unlocked.destroy()
	encrypted, err := s.client.ListEncryptedResources(ctx, vaultURI, resourceType)
	if err != nil {
		return nil, err
	}
	result := make([]DecryptedResource, 0, len(encrypted))
	for _, item := range encrypted {
		resource, err := decryptResource(item, unlocked, resourceType)
		if err != nil {
			return nil, err
		}
		result = append(result, resource)
	}
	return result, nil
}

func (s *E2EEService) GetResourceByName(ctx context.Context, vaultURI, resourceType, name string) (DecryptedResource, error) {
	unlocked, err := s.unlock(ctx, vaultURI)
	if err != nil {
		return DecryptedResource{}, err
	}
	defer unlocked.destroy()
	nameIndex, err := secryncrypto.NameIndexHex(unlocked.vek, unlocked.id, name)
	if err != nil {
		return DecryptedResource{}, err
	}
	encrypted, err := s.client.GetEncryptedResourceByIndex(ctx, vaultURI, resourceType, nameIndex)
	if err != nil {
		return DecryptedResource{}, err
	}
	return decryptResource(encrypted, unlocked, resourceType)
}

func (s *E2EEService) GetResourceByID(ctx context.Context, vaultURI, resourceType, id string) (DecryptedResource, error) {
	unlocked, err := s.unlock(ctx, vaultURI)
	if err != nil {
		return DecryptedResource{}, err
	}
	defer unlocked.destroy()
	encrypted, err := s.client.GetEncryptedResource(ctx, vaultURI, resourceType, id)
	if err != nil {
		return DecryptedResource{}, err
	}
	return decryptResource(encrypted, unlocked, resourceType)
}

func (s *E2EEService) unlock(ctx context.Context, vaultURI string) (*unlockedVault, error) {
	envelope, err := s.client.GetVaultKeyEnvelope(ctx, vaultURI, s.identity.RecipientID())
	if err != nil {
		return nil, err
	}
	privateKey := s.identity.PrivateKey()
	defer wipe(privateKey)
	vek, err := secryncrypto.UnwrapVEKForRecipient(
		envelope.CryptoEnvelope(),
		privateKey,
		secryncrypto.RecipientContext{
			VaultID: envelope.VaultID, RecipientID: envelope.RecipientID, KeyVersion: envelope.KeyVersion,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unwrap vault encryption key: %w", err)
	}
	return &unlockedVault{id: envelope.VaultID, keyVersion: envelope.KeyVersion, vek: vek}, nil
}

func decryptSecret(item client.EncryptedSecret, unlocked *unlockedVault) (client.Secret, error) {
	if unlocked == nil || len(unlocked.vek) != secryncrypto.VEKSize || item.VaultID != unlocked.id || item.KeyVersion != unlocked.keyVersion {
		return client.Secret{}, ErrEnvelopeMismatch
	}
	plaintext, err := secryncrypto.DecryptResource(
		item.CryptoEnvelope(),
		unlocked.vek,
		secryncrypto.ResourceContext{
			VaultID: item.VaultID, ResourceType: "secret", ResourceID: item.ID,
			AADVersion: item.AADVersion, KeyVersion: item.KeyVersion,
		},
	)
	if err != nil {
		return client.Secret{}, fmt.Errorf("decrypt secret: %w", err)
	}
	defer wipe(plaintext)
	if len(plaintext) > maxDecryptedSecretPayload || !utf8.Valid(plaintext) {
		return client.Secret{}, ErrInvalidPayload
	}
	var payload decryptedPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil || payload.Name == nil || payload.Value == nil {
		return client.Secret{}, ErrInvalidPayload
	}
	expectedIndex, err := secryncrypto.NameIndex(unlocked.vek, unlocked.id, *payload.Name)
	if err != nil {
		return client.Secret{}, ErrInvalidPayload
	}
	actualIndex, err := hex.DecodeString(item.NameIndex)
	if err != nil || subtle.ConstantTimeCompare(actualIndex, expectedIndex) != 1 {
		return client.Secret{}, ErrEnvelopeMismatch
	}
	return client.Secret{Name: *payload.Name, Value: *payload.Value, UpdatedAt: item.UpdatedAt}, nil
}

func decryptResource(item client.EncryptedResource, unlocked *unlockedVault, resourceType string) (DecryptedResource, error) {
	if resourceType != "key" && resourceType != "certificate" {
		return DecryptedResource{}, ErrInvalidPayload
	}
	if unlocked == nil || len(unlocked.vek) != secryncrypto.VEKSize || item.VaultID != unlocked.id || item.KeyVersion != unlocked.keyVersion {
		return DecryptedResource{}, ErrEnvelopeMismatch
	}
	plaintext, err := secryncrypto.DecryptResource(item.CryptoEnvelope(), unlocked.vek, secryncrypto.ResourceContext{
		VaultID: item.VaultID, ResourceType: resourceType, ResourceID: item.ID, AADVersion: item.AADVersion, KeyVersion: item.KeyVersion,
	})
	if err != nil {
		return DecryptedResource{}, fmt.Errorf("decrypt %s: %w", resourceType, err)
	}
	defer wipe(plaintext)
	if len(plaintext) > maxDecryptedSecretPayload || !utf8.Valid(plaintext) {
		return DecryptedResource{}, ErrInvalidPayload
	}
	result := DecryptedResource{ID: item.ID, UpdatedAt: item.UpdatedAt}
	var name string
	switch resourceType {
	case "key":
		var payload keyPayload
		if strictJSON(plaintext, &payload) != nil || payload.Name == nil || *payload.Name == "" || payload.Material == nil ||
			(payload.Material.PEMPrivate == "" && payload.Material.OpenSSHPrivate == "" && payload.Material.PEMPublic == "" && payload.Material.OpenSSHPublic == "") ||
			(payload.KeySize != nil && *payload.KeySize <= 0) {
			return DecryptedResource{}, ErrInvalidPayload
		}
		name = *payload.Name
		result.Name, result.Material, result.KeyType, result.KeyCurve, result.OutputFormat, result.Tags = name, payload.Material, payload.KeyType, payload.KeyCurve, payload.OutputFormat, payload.Tags
		if payload.KeySize != nil {
			result.KeySize = *payload.KeySize
		}
	case "certificate":
		var payload certificatePayload
		if strictJSON(plaintext, &payload) != nil || payload.Name == nil || *payload.Name == "" || payload.CertificatePEM == nil || *payload.CertificatePEM == "" ||
			(payload.PrivateKeyPEM != nil && *payload.PrivateKeyPEM == "") {
			return DecryptedResource{}, ErrInvalidPayload
		}
		name = *payload.Name
		result.Name, result.CertificatePEM, result.Tags = name, *payload.CertificatePEM, payload.Tags
		if payload.PrivateKeyPEM != nil {
			result.PrivateKeyPEM = *payload.PrivateKeyPEM
		}
	}
	expectedIndex, err := secryncrypto.NameIndex(unlocked.vek, unlocked.id, name)
	if err != nil {
		return DecryptedResource{}, ErrInvalidPayload
	}
	actualIndex, err := hex.DecodeString(item.NameIndex)
	if err != nil || subtle.ConstantTimeCompare(actualIndex, expectedIndex) != 1 {
		return DecryptedResource{}, ErrEnvelopeMismatch
	}
	return result, nil
}

func strictJSON(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.More() {
		return ErrInvalidPayload
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidPayload
	}
	return nil
}

func (u *unlockedVault) destroy() {
	if u == nil {
		return
	}
	wipe(u.vek)
	u.vek = nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}
