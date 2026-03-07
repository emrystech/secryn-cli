package client

// Secret represents a secret record returned by the Secryn API.
type Secret struct {
	Name      string `json:"name"`
	Value     string `json:"value,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Key represents a key record returned by the Secryn API.
type Key struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// Certificate represents a certificate record returned by the Secryn API.
type Certificate struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}
