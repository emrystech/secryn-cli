package client

import secryncrypto "github.com/secryn/secryn-cli/internal/crypto"

// Secret represents a secret record returned by the Secryn API.
type Secret struct {
	Name      string `json:"name"`
	Value     string `json:"value,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// VaultKeyEnvelope is the server's ciphertext-only envelope for one recipient.
type VaultKeyEnvelope struct {
	Version            int    `json:"version"`
	VaultID            string `json:"vault_id"`
	RecipientID        string `json:"recipient_id"`
	KeyVersion         int    `json:"key_version"`
	Algorithm          string `json:"algorithm"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
}

func (e VaultKeyEnvelope) CryptoEnvelope() secryncrypto.RecipientEnvelope {
	return secryncrypto.RecipientEnvelope{
		Version:            e.Version,
		KeyVersion:         e.KeyVersion,
		Algorithm:          e.Algorithm,
		EphemeralPublicKey: e.EphemeralPublicKey,
		Nonce:              e.Nonce,
		Ciphertext:         e.Ciphertext,
	}
}

// EncryptedSecret is an opaque E2EE resource returned by API v2.
type EncryptedSecret struct {
	ID         string                          `json:"id"`
	VaultID    string                          `json:"vault_id"`
	NameIndex  string                          `json:"name_index"`
	Version    int                             `json:"version"`
	AADVersion int                             `json:"aad_version"`
	KeyVersion int                             `json:"key_version"`
	Nonce      string                          `json:"nonce"`
	Ciphertext string                          `json:"ciphertext"`
	WrappedDEK secryncrypto.WrappedKeyEnvelope `json:"wrapped_dek"`
	Enabled    bool                            `json:"enabled"`
	NotBefore  *string                         `json:"not_before,omitempty"`
	ExpiresAt  *string                         `json:"expires_at,omitempty"`
	CreatedAt  string                          `json:"created_at,omitempty"`
	UpdatedAt  string                          `json:"updated_at,omitempty"`
}

func (s EncryptedSecret) CryptoEnvelope() secryncrypto.ResourceEnvelope {
	return secryncrypto.ResourceEnvelope{
		Version:    s.Version,
		AADVersion: s.AADVersion,
		KeyVersion: s.KeyVersion,
		Nonce:      s.Nonce,
		Ciphertext: s.Ciphertext,
		WrappedDEK: s.WrappedDEK,
	}
}

// EncryptedSecretWrite is the API v2 ciphertext-only create/update payload.
type EncryptedSecretWrite struct {
	ID         string                          `json:"id,omitempty"`
	NameIndex  string                          `json:"name_index"`
	Version    int                             `json:"version"`
	AADVersion int                             `json:"aad_version"`
	KeyVersion int                             `json:"key_version"`
	Nonce      string                          `json:"nonce"`
	Ciphertext string                          `json:"ciphertext"`
	WrappedDEK secryncrypto.WrappedKeyEnvelope `json:"wrapped_dek"`
	Enabled    bool                            `json:"enabled"`
	NotBefore  *string                         `json:"not_before,omitempty"`
	ExpiresAt  *string                         `json:"expires_at,omitempty"`
}

// Key represents a key record returned by the Secryn API.
type Key struct {
	ID             string `json:"id"`
	Name           string `json:"name,omitempty"`
	Type           string `json:"type,omitempty"`
	KeyType        string `json:"key_type,omitempty"`
	KeySize        int    `json:"key_size,omitempty"`
	KeyCurve       string `json:"key_curve,omitempty"`
	OutputFormat   string `json:"output_format,omitempty"`
	ActivationDate string `json:"activation_date,omitempty"`
	ExpirationDate string `json:"expiration_date,omitempty"`
	Algorithm      string `json:"algorithm,omitempty"`
	CreatedAt      string `json:"created_at,omitempty"`
}

// Certificate represents a certificate record returned by the Secryn API.
type Certificate struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Type      string `json:"type,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}
