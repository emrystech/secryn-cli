package client

// Secret represents a secret record returned by the Secryn API.
type Secret struct {
	Name      string `json:"name"`
	Value     string `json:"value,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
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
