package crypto

import "errors"

var (
	ErrInvalidEnvelope    = errors.New("invalid encryption envelope")
	ErrInvalidKey         = errors.New("invalid encryption key")
	ErrDecryptionFailed   = errors.New("decryption failed")
	ErrInvalidName        = errors.New("invalid resource name")
	ErrInvalidVaultID     = errors.New("invalid vault ID")
	ErrUnsupportedVersion = errors.New("unsupported encryption envelope version")
)
