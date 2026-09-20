package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/secryn/secryn-cli/internal/client"
	"github.com/secryn/secryn-cli/internal/config"
	secryncrypto "github.com/secryn/secryn-cli/internal/crypto"
)

type commandLifecycleRoundTripFunc func(*http.Request) (*http.Response, error)

func (f commandLifecycleRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestE2EEInitPersistsIdentityOnlyAfterVerifiedBootstrap(t *testing.T) {
	const canonicalVaultID = "11111111-1111-4111-8111-111111111111"
	configPath := filepath.Join(t.TempDir(), "secryn", "config.yaml")
	if err := config.Save(configPath, config.Config{BaseURL: "https://example.test", VaultID: "vault-uri", AccessKey: "access-key"}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	transport := commandLifecycleRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		call := calls.Add(1)
		if request.Header.Get("Authorization") != "Bearer access-key" {
			t.Fatal("lifecycle request omitted access-key authentication")
		}
		switch call {
		case 1:
			if request.Method != http.MethodGet || request.URL.Path != "/v2/vaults/vault-uri/crypto/context" {
				t.Fatalf("unexpected context request: %s %s", request.Method, request.URL.Path)
			}
			return commandLifecycleResponse(http.StatusOK, map[string]any{
				"version": 1, "vault_id": canonicalVaultID, "encryption_mode": "legacy", "key_version": nil, "bootstrap_eligible": true,
			}), nil
		case 2:
			var provision client.RecipientProvisionRequest
			if err := json.NewDecoder(request.Body).Decode(&provision); err != nil {
				t.Fatal(err)
			}
			if request.Method != http.MethodPost || request.URL.Path != "/v2/vaults/vault-uri/crypto/bootstrap" ||
				!validLifecycleUUID(provision.Recipient.ID) || provision.Envelope.KeyVersion != 1 {
				t.Fatal("unexpected bootstrap request")
			}
			staged, err := config.Load(configPath)
			if err != nil || !staged.E2EEBootstrapPending || staged.RecipientID != provision.Recipient.ID || staged.RecipientPrivateKey == "" {
				t.Fatal("identity was not securely staged before bootstrap dispatch")
			}
			return commandLifecycleResponse(http.StatusCreated, map[string]any{
				"version": 1, "vault_id": canonicalVaultID, "encryption_mode": "e2ee", "key_version": 1,
				"recipient": map[string]any{
					"id": provision.Recipient.ID, "type": provision.Recipient.Type, "label": provision.Recipient.Label,
					"public_key": provision.Recipient.PublicKey, "public_key_fingerprint": provision.Recipient.PublicKeyFingerprint, "status": "active",
				},
				"envelope": provision.Envelope,
			}), nil
		default:
			t.Fatal("unexpected extra lifecycle request")
			return nil, nil
		}
	})

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.httpClient = &http.Client{Transport: transport}
	app.envLookup = func(string) string { return "" }
	if code := app.ExecuteArgs([]string{"e2ee", "init", "--config", configPath}); code != exitOK {
		t.Fatalf("e2ee init exit code = %d, stderr = %s", code, stderr.String())
	}
	saved, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := base64.RawURLEncoding.Strict().DecodeString(saved.RecipientPrivateKey)
	if err != nil || len(privateKey) != 32 || !validLifecycleUUID(saved.RecipientID) {
		t.Fatal("persisted identity is malformed")
	}
	if saved.E2EEBootstrapPending {
		t.Fatal("successful bootstrap left identity pending")
	}
	if strings.Contains(stdout.String(), saved.RecipientPrivateKey) {
		t.Fatal("private key was printed")
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %v", info.Mode().Perm())
	}
	if calls.Load() != 2 {
		t.Fatalf("lifecycle request count = %d", calls.Load())
	}
}

func TestE2EEInitRetainsAndRecoversIdentityAfterAmbiguousDispatch(t *testing.T) {
	const canonicalVaultID = "11111111-1111-4111-8111-111111111111"
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := config.Save(configPath, config.Config{BaseURL: "https://example.test", VaultID: "vault-uri", AccessKey: "access-key"}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var committed client.RecipientProvisionRequest
	transport := commandLifecycleRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return commandLifecycleResponse(http.StatusOK, map[string]any{
				"version": 1, "vault_id": canonicalVaultID, "encryption_mode": "legacy", "key_version": nil, "bootstrap_eligible": true,
			}), nil
		case 2:
			if err := json.NewDecoder(request.Body).Decode(&committed); err != nil {
				t.Fatal(err)
			}
			staged, err := config.Load(configPath)
			if err != nil || !staged.E2EEBootstrapPending || staged.RecipientID != committed.Recipient.ID {
				t.Fatal("ambiguous dispatch did not have a recoverable staged identity")
			}
			// Simulate a response transport failure after the server committed.
			return nil, io.ErrUnexpectedEOF
		case 3:
			return commandLifecycleResponse(http.StatusOK, map[string]any{
				"version": 1, "vault_id": canonicalVaultID, "encryption_mode": "e2ee", "key_version": 1, "bootstrap_eligible": false,
			}), nil
		case 4:
			if request.Header.Get("X-Secryn-Recipient-ID") != committed.Recipient.ID {
				t.Fatal("recovery requested the wrong recipient envelope")
			}
			return commandLifecycleResponse(http.StatusOK, map[string]any{
				"version": 1, "vault_id": canonicalVaultID, "recipient_id": committed.Recipient.ID,
				"key_version": committed.Envelope.KeyVersion, "algorithm": committed.Envelope.Algorithm,
				"ephemeral_public_key": committed.Envelope.EphemeralPublicKey, "nonce": committed.Envelope.Nonce,
				"ciphertext": committed.Envelope.Ciphertext,
			}), nil
		default:
			t.Fatal("unexpected recovery request")
			return nil, nil
		}
	})

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.httpClient = &http.Client{Transport: transport}
	app.envLookup = func(string) string { return "" }
	if code := app.ExecuteArgs([]string{"e2ee", "init", "--config", configPath}); code != exitGeneric {
		t.Fatalf("ambiguous bootstrap exit code = %d", code)
	}
	pending, err := config.Load(configPath)
	if err != nil || !pending.E2EEBootstrapPending || pending.RecipientPrivateKey == "" {
		t.Fatal("ambiguous bootstrap did not retain pending identity")
	}
	if !strings.Contains(stderr.String(), "Rerun `secryn e2ee init`") || strings.Contains(stderr.String(), pending.RecipientPrivateKey) {
		t.Fatal("ambiguous bootstrap guidance was missing or exposed private material")
	}

	stdout.Reset()
	stderr.Reset()
	app = NewApp(stdout, stderr)
	app.httpClient = &http.Client{Transport: transport}
	app.envLookup = func(string) string { return "" }
	if code := app.ExecuteArgs([]string{"e2ee", "init", "--config", configPath}); code != exitOK {
		t.Fatalf("bootstrap recovery exit code = %d, stderr = %s", code, stderr.String())
	}
	recovered, err := config.Load(configPath)
	if err != nil || recovered.E2EEBootstrapPending || recovered.RecipientID != committed.Recipient.ID {
		t.Fatal("bootstrap recovery did not finalize the retained identity")
	}
	if !strings.Contains(stdout.String(), "recovered") {
		t.Fatal("bootstrap recovery was not explicit")
	}
}

func TestE2EEInitRestoresOriginalConfigAfterDefinitiveRejection(t *testing.T) {
	const canonicalVaultID = "11111111-1111-4111-8111-111111111111"
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	original := config.Config{BaseURL: "https://example.test", VaultID: "vault-uri", AccessKey: "access-key"}
	if err := config.Save(configPath, original); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	transport := commandLifecycleRoundTripFunc(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return commandLifecycleResponse(http.StatusOK, map[string]any{
				"version": 1, "vault_id": canonicalVaultID, "encryption_mode": "legacy", "key_version": nil, "bootstrap_eligible": true,
			}), nil
		}
		return commandLifecycleResponse(http.StatusUnprocessableEntity, map[string]any{"message": "rejected"}), nil
	})
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.httpClient = &http.Client{Transport: transport}
	app.envLookup = func(string) string { return "" }
	if code := app.ExecuteArgs([]string{"e2ee", "init", "--config", configPath}); code != exitUsage {
		t.Fatalf("definitive rejection exit code = %d, stderr = %s", code, stderr.String())
	}
	restored, err := config.Load(configPath)
	if err != nil || restored != original {
		t.Fatalf("config was not restored: %#v, %v", restored, err)
	}
}

func TestE2EEInitRetainsIdentityWhenSuccessResponseIsSubstituted(t *testing.T) {
	const canonicalVaultID = "11111111-1111-4111-8111-111111111111"
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := config.Save(configPath, config.Config{BaseURL: "https://example.test", VaultID: "vault-uri", AccessKey: "access-key"}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	transport := commandLifecycleRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return commandLifecycleResponse(http.StatusOK, map[string]any{
				"version": 1, "vault_id": canonicalVaultID, "encryption_mode": "legacy", "key_version": nil, "bootstrap_eligible": true,
			}), nil
		}
		var provision client.RecipientProvisionRequest
		if err := json.NewDecoder(request.Body).Decode(&provision); err != nil {
			t.Fatal(err)
		}
		return commandLifecycleResponse(http.StatusCreated, map[string]any{
			"version": 1, "vault_id": canonicalVaultID, "encryption_mode": "e2ee", "key_version": 1,
			"recipient": map[string]any{
				"id": "99999999-9999-4999-8999-999999999999", "type": provision.Recipient.Type, "label": provision.Recipient.Label,
				"public_key": provision.Recipient.PublicKey, "public_key_fingerprint": provision.Recipient.PublicKeyFingerprint, "status": "active",
			},
			"envelope": provision.Envelope,
		}), nil
	})
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.httpClient = &http.Client{Transport: transport}
	app.envLookup = func(string) string { return "" }
	if code := app.ExecuteArgs([]string{"e2ee", "init", "--config", configPath}); code != exitGeneric {
		t.Fatalf("substituted response exit code = %d", code)
	}
	pending, err := config.Load(configPath)
	if err != nil || !pending.E2EEBootstrapPending || pending.RecipientPrivateKey == "" {
		t.Fatal("substituted success response did not retain pending identity")
	}
	if strings.Contains(stdout.String()+stderr.String(), pending.RecipientPrivateKey) {
		t.Fatal("substitution handling exposed private key")
	}
}

func TestPendingBootstrapBlocksAllNonInitCommandsBeforeNetwork(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	pending := config.Config{
		BaseURL: "https://example.test", VaultID: "vault-uri", AccessKey: "access-key",
		RecipientID: "11111111-1111-4111-8111-111111111111", RecipientPrivateKey: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32)),
		E2EEBootstrapPending: true,
	}
	if err := config.Save(configPath, pending); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{
		{"secret", "list", "--config", configPath},
		{"e2ee", "rotate", "--config", configPath},
		{"mcp", "serve", "--config", configPath},
		{"update", "--check", "--config", configPath},
	} {
		t.Run(strings.Join(arguments[:2], "_"), func(t *testing.T) {
			var calls atomic.Int32
			stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
			app := NewApp(stdout, stderr)
			app.httpClient = &http.Client{Transport: commandLifecycleRoundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return commandLifecycleResponse(http.StatusInternalServerError, nil), nil
			})}
			app.envLookup = func(string) string { return "" }
			if code := app.ExecuteArgs(arguments); code != exitUsage {
				t.Fatalf("pending command exit code = %d, stderr = %s", code, stderr.String())
			}
			if calls.Load() != 0 {
				t.Fatal("pending command reached the network")
			}
			if !strings.Contains(stderr.String(), "rerun `secryn e2ee init`") {
				t.Fatalf("pending command lacked recovery guidance: %s", stderr.String())
			}
		})
	}
}

func TestE2EEInitRejectsEnvironmentOverridesBeforeNetwork(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := config.Save(configPath, config.Config{BaseURL: "https://example.test", VaultID: "vault-uri", AccessKey: "access-key"}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.httpClient = &http.Client{Transport: commandLifecycleRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return commandLifecycleResponse(http.StatusInternalServerError, nil), nil
	})}
	app.envLookup = func(name string) string {
		if name == "SECRYN_VAULT_ID" {
			return "environment-vault"
		}
		return ""
	}
	if code := app.ExecuteArgs([]string{"e2ee", "init", "--config", configPath}); code != exitUsage {
		t.Fatalf("e2ee init exit code = %d, want %d", code, exitUsage)
	}
	if calls.Load() != 0 {
		t.Fatal("ambiguous lifecycle configuration reached the network")
	}
}

func TestE2EERotateEmptyVaultCreatesRecipientEnvelopeAndCommits(t *testing.T) {
	const (
		canonicalVaultID = "11111111-1111-4111-8111-111111111111"
		recipientID      = "22222222-2222-4222-8222-222222222222"
		rotationID       = "33333333-3333-4333-8333-333333333333"
	)
	keyPair, err := secryncrypto.GenerateRecipientKeyPairWithRandom(bytes.NewReader(bytes.Repeat([]byte{0x31}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	oldVEK := bytes.Repeat([]byte{0x32}, 32)
	currentEnvelope, err := secryncrypto.WrapVEKForRecipientWithRandom(oldVEK, keyPair.PublicKey, secryncrypto.RecipientContext{
		VaultID: canonicalVaultID, RecipientID: recipientID, KeyVersion: 1,
	}, bytes.NewReader(bytes.Repeat([]byte{0x33}, 56)))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(keyPair.PublicKey)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := config.Save(configPath, config.Config{
		BaseURL: "https://example.test", VaultID: "vault-uri", AccessKey: "access-key", RecipientID: recipientID,
		RecipientPrivateKey: base64.RawURLEncoding.EncodeToString(keyPair.PrivateKey),
	}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	transport := commandLifecycleRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		call := calls.Add(1)
		switch call {
		case 1:
			if request.URL.Path != "/v2/vaults/vault-uri/crypto/context" {
				t.Fatal("unexpected crypto context request")
			}
			return commandLifecycleResponse(http.StatusOK, map[string]any{
				"version": 1, "vault_id": canonicalVaultID, "encryption_mode": "e2ee", "key_version": 1, "bootstrap_eligible": false,
			}), nil
		case 2:
			if request.URL.Path != "/v2/vaults/vault-uri/crypto/envelope" || request.Header.Get("X-Secryn-Recipient-ID") != recipientID {
				t.Fatal("unexpected current envelope request")
			}
			return commandLifecycleResponse(http.StatusOK, map[string]any{
				"version": 1, "vault_id": canonicalVaultID, "recipient_id": recipientID, "key_version": 1,
				"algorithm": currentEnvelope.Algorithm, "ephemeral_public_key": currentEnvelope.EphemeralPublicKey,
				"nonce": currentEnvelope.Nonce, "ciphertext": currentEnvelope.Ciphertext,
			}), nil
		case 3:
			if request.URL.Path != "/v2/vaults/vault-uri/crypto/recipients" {
				t.Fatal("recipient list did not use configured vault URI")
			}
			return commandLifecycleResponse(http.StatusOK, map[string]any{"version": 1, "data": []any{map[string]any{
				"id": recipientID, "type": "cli", "label": "CLI", "public_key": base64.RawURLEncoding.EncodeToString(keyPair.PublicKey),
				"public_key_fingerprint": hex.EncodeToString(digest[:]), "status": "active", "created_at": "2026-01-01T00:00:00Z",
			}}}), nil
		case 4:
			if request.URL.Path != "/v2/vaults/vault-uri/crypto/rotations" {
				t.Fatal("rotation start did not use configured vault URI")
			}
			var input client.RotationCreateRequest
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Fatal(err)
			}
			if len(input.RecipientEnvelopes) != 1 || input.RecipientEnvelopes[0].RecipientID != recipientID || input.RecipientEnvelopes[0].KeyVersion != 2 {
				t.Fatal("rotation did not contain the active recipient's target envelope")
			}
			return commandLifecycleResponse(http.StatusCreated, map[string]any{"version": 1, "data": map[string]any{
				"id": rotationID, "from_key_version": 1, "to_key_version": 2, "status": "pending",
				"expected_secrets": 0, "expected_secret_versions": 0, "staged": 0, "committed_at": nil,
			}}), nil
		case 5, 6, 7, 8:
			if !strings.HasPrefix(request.URL.Path, "/v2/vaults/vault-uri/crypto/rotations/") {
				t.Fatal("rotation source did not use configured vault URI")
			}
			kind := request.URL.Query().Get("kind")
			expectedKinds := map[int32]string{5: "secret", 6: "secret_version", 7: "key", 8: "certificate"}
			if kind != expectedKinds[call] {
				t.Fatalf("unexpected rotation source kind %q", kind)
			}
			return commandLifecycleResponse(http.StatusOK, map[string]any{"version": 1, "data": []any{}, "meta": map[string]any{"next_cursor": nil}}), nil
		case 9:
			if request.Method != http.MethodPost || request.URL.Path != "/v2/vaults/vault-uri/crypto/rotations/"+rotationID+"/commit" {
				t.Fatal("unexpected rotation commit request")
			}
			return commandLifecycleResponse(http.StatusOK, map[string]any{"version": 1, "data": map[string]any{
				"id": rotationID, "from_key_version": 1, "to_key_version": 2, "status": "committed",
				"expected_secrets": 0, "expected_secret_versions": 0, "staged": 0, "committed_at": "2026-01-01T00:00:00Z",
			}}), nil
		default:
			t.Fatal("unexpected extra rotation request")
			return nil, nil
		}
	})
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.httpClient = &http.Client{Transport: transport}
	app.envLookup = func(string) string { return "" }
	if code := app.ExecuteArgs([]string{"e2ee", "rotate", "--config", configPath}); code != exitOK {
		t.Fatalf("e2ee rotate exit code = %d, stderr = %s", code, stderr.String())
	}
	if calls.Load() != 9 || !strings.Contains(stdout.String(), "version 1 to 2") {
		t.Fatalf("unexpected rotation result: calls=%d output=%q", calls.Load(), stdout.String())
	}
}

func TestRandomUUIDProducesRFC4122VariantVersion(t *testing.T) {
	value, err := randomUUID()
	if err != nil || !validLifecycleUUID(value) || value[14] != '4' || !strings.Contains("89ab", strings.ToLower(value[19:20])) {
		t.Fatalf("randomUUID() = %q, %v", value, err)
	}
}

func TestPendingRotationErrorProvidesExactCancellationGuidance(t *testing.T) {
	const rotationID = "33333333-3333-4333-8333-333333333333"
	err := pendingRotationError(rotationID, io.ErrUnexpectedEOF)
	if !strings.Contains(err.Error(), "secryn e2ee rotation cancel "+rotationID) || !strings.Contains(err.Error(), "remains pending") {
		t.Fatalf("pendingRotationError() = %q", err.Error())
	}
}

func TestRotationResourceTypeRejectsSubstitutedResourceIDs(t *testing.T) {
	storageID := "11111111-1111-4111-8111-111111111111"
	otherID := "22222222-2222-4222-8222-222222222222"
	for _, kind := range []string{"secret", "key", "certificate"} {
		if _, err := rotationResourceType(kind, client.RotationSourceItem{StorageID: storageID, ResourceID: otherID}); err == nil {
			t.Fatalf("%s rotation source accepted a substituted resource ID", kind)
		}
		if got, err := rotationResourceType(kind, client.RotationSourceItem{StorageID: storageID, ResourceID: storageID}); err != nil || got != kind {
			t.Fatalf("%s valid rotation source = %q, %v", kind, got, err)
		}
	}
	if got, err := rotationResourceType("secret_version", client.RotationSourceItem{StorageID: storageID, ResourceID: otherID}); err != nil || got != "secret" {
		t.Fatalf("secret version parent binding = %q, %v", got, err)
	}
}

func TestVerifyRotationSourceDigestRejectsEnvelopeSubstitution(t *testing.T) {
	source := client.RotationSourceItem{
		Kind: "secret_version", StorageID: "11111111-1111-4111-8111-111111111111",
		ResourceID: "22222222-2222-4222-8222-222222222222", VaultID: "33333333-3333-4333-8333-333333333333",
		NameIndex: strings.Repeat("a", 64), Version: 1, AADVersion: 1, KeyVersion: 1,
		Nonce:      base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 24)),
		Ciphertext: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
		WrappedDEK: secryncrypto.WrappedKeyEnvelope{
			Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 48)),
		},
	}
	canonicalA := strings.Join([]string{
		"secryn-rotation-source-v1", source.Kind, source.StorageID, source.ResourceID, source.VaultID, source.NameIndex,
		"1", "1", "1", source.Nonce, source.Ciphertext, source.WrappedDEK.Nonce, source.WrappedDEK.Ciphertext,
	}, "\x00")
	digestA := sha256.Sum256([]byte(canonicalA))
	source.SourceDigest = hex.EncodeToString(digestA[:])
	if err := verifyRotationSourceDigest(source); err != nil {
		t.Fatalf("valid source digest rejected: %v", err)
	}

	// Preserve storage/digest A while substituting all encrypted fields from B.
	source.Nonce = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 24))
	source.Ciphertext = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 32))
	source.WrappedDEK.Nonce = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, 24))
	source.WrappedDEK.Ciphertext = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x54}, 48))
	if err := verifyRotationSourceDigest(source); err == nil {
		t.Fatal("rotation source accepted storage/digest A with encrypted envelope B")
	}
}

func commandLifecycleResponse(status int, body any) *http.Response {
	payload, _ := json.Marshal(body)
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(payload))}
}
