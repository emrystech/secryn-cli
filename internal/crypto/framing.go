package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// frame encodes each field as an unsigned 32-bit big-endian length followed by
// its bytes. This prevents ambiguity between adjacent variable-length fields.
func frame(fields ...[]byte) ([]byte, error) {
	total := 0
	for _, field := range fields {
		if uint64(len(field)) > uint64(^uint32(0)) {
			return nil, fmt.Errorf("frame field is too large: %w", ErrInvalidEnvelope)
		}
		if total > int(^uint(0)>>1)-4-len(field) {
			return nil, fmt.Errorf("frame is too large: %w", ErrInvalidEnvelope)
		}
		total += 4 + len(field)
	}

	result := make([]byte, 0, total)
	var size [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		result = append(result, size[:]...)
		result = append(result, field...)
	}
	return result, nil
}

// DeriveKey derives length bytes using HKDF-SHA-256. Callers must supply a
// protocol-specific info value; nil input key material is rejected.
func DeriveKey(inputKeyMaterial, salt, info []byte, length int) ([]byte, error) {
	if len(inputKeyMaterial) == 0 {
		return nil, ErrInvalidKey
	}
	if length <= 0 || length > 255*32 {
		return nil, fmt.Errorf("invalid HKDF output length: %w", ErrInvalidKey)
	}

	derived := make([]byte, length)
	reader := hkdf.New(sha256.New, inputKeyMaterial, salt, info)
	if _, err := io.ReadFull(reader, derived); err != nil {
		return nil, errors.Join(ErrInvalidKey, err)
	}
	return derived, nil
}
