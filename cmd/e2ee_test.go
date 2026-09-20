package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/secryn/secryn-cli/internal/client"
	secryncrypto "github.com/secryn/secryn-cli/internal/crypto"
	secretservice "github.com/secryn/secryn-cli/internal/secrets"
)

func TestE2EEEnvPullDecryptsLocallyWithoutLegacyFallback(t *testing.T) {
	server, environment, legacyRequests := newCommandE2EEFixture(t)
	defer server.Close()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.httpClient = server.Client()
	app.envLookup = func(name string) string { return environment[name] }

	exitCode := app.ExecuteArgs([]string{"env", "pull", "--config", filepath.Join(t.TempDir(), "missing.yaml")})
	if exitCode != exitOK {
		t.Fatalf("env pull exit code = %d", exitCode)
	}
	if stdout.String() != "PIPELINE_TOKEN=fixture-value\n" {
		t.Fatal("env pull did not emit the expected locally decrypted environment entry")
	}
	if stderr.Len() != 0 || legacyRequests.Load() != 0 {
		t.Fatal("E2EE env pull produced an error or attempted a legacy request")
	}
}

func TestE2EEAuthAndConfigDiagnosticsExposeModeNotPrivateKey(t *testing.T) {
	server, environment, _ := newCommandE2EEFixture(t)
	defer server.Close()
	configPath := filepath.Join(t.TempDir(), "missing.yaml")

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.httpClient = server.Client()
	app.envLookup = func(name string) string { return environment[name] }
	if exitCode := app.ExecuteArgs([]string{"auth", "test", "--json", "--config", configPath}); exitCode != exitOK {
		t.Fatalf("auth test exit code = %d", exitCode)
	}
	var authResult map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &authResult); err != nil {
		t.Fatal(err)
	}
	if authResult["encryption_mode"] != "e2ee" || authResult["ok"] != true {
		t.Fatal("auth diagnostics did not report successful E2EE mode")
	}

	stdout.Reset()
	stderr.Reset()
	app = NewApp(stdout, stderr)
	app.envLookup = func(name string) string { return environment[name] }
	if exitCode := app.ExecuteArgs([]string{"config", "show", "--json", "--config", configPath}); exitCode != exitOK {
		t.Fatalf("config show exit code = %d", exitCode)
	}
	if strings.Contains(stdout.String(), environment["SECRYN_RECIPIENT_PRIVATE_KEY"]) {
		t.Fatal("config diagnostics exposed the recipient private key")
	}
	var configResult map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &configResult); err != nil {
		t.Fatal(err)
	}
	if configResult["encryption_mode"] != "e2ee" || configResult["recipient_id"] != "11111111-1111-4111-8111-111111111111" {
		t.Fatal("config diagnostics did not expose safe E2EE metadata")
	}
}

func TestPartialE2EEIdentityFailsBeforeNetworkRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp(stdout, stderr)
	app.httpClient = server.Client()
	app.envLookup = func(name string) string {
		values := map[string]string{
			"SECRYN_BASE_URL": server.URL, "SECRYN_VAULT_ID": "vault-uri",
			"SECRYN_ACCESS_KEY": "access-token", "SECRYN_RECIPIENT_ID": "11111111-1111-4111-8111-111111111111",
		}
		return values[name]
	}
	if exitCode := app.ExecuteArgs([]string{"secret", "list", "--config", filepath.Join(t.TempDir(), "missing.yaml")}); exitCode != exitUsage {
		t.Fatalf("partial identity exit code = %d, want %d", exitCode, exitUsage)
	}
	if requests.Load() != 0 {
		t.Fatal("partial E2EE identity reached the network")
	}
}

func TestEnvPullRejectsInvalidNamesWithoutPartialOutput(t *testing.T) {
	tests := []string{"LINE\nBREAK", "HAS=EQUALS", "HAS SPACE", "HAS\tCONTROL"}
	for _, invalidName := range tests {
		t.Run("invalid", func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode([]client.Secret{
					{Name: "VALID_FIRST", Value: "fixture-one"},
					{Name: invalidName, Value: "fixture-two"},
				})
			}))
			defer server.Close()
			stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
			app := NewApp(stdout, stderr)
			app.httpClient = server.Client()
			app.envLookup = func(name string) string {
				values := map[string]string{
					"SECRYN_BASE_URL": server.URL, "SECRYN_VAULT_ID": "vault-uri", "SECRYN_ACCESS_KEY": "access-token",
				}
				return values[name]
			}
			if exitCode := app.ExecuteArgs([]string{"env", "pull", "--config", filepath.Join(t.TempDir(), "missing.yaml")}); exitCode != exitUsage {
				t.Fatalf("env pull exit code = %d, want %d", exitCode, exitUsage)
			}
			if stdout.Len() != 0 {
				t.Fatal("env pull emitted partial plaintext before rejecting an invalid name")
			}
		})
	}
}

func TestValidEnvName(t *testing.T) {
	for _, name := range []string{"A", "_PRIVATE", "lower_2", "DATABASE_URL"} {
		if !validEnvName(name) {
			t.Fatalf("validEnvName() rejected %q", name)
		}
	}
	for _, name := range []string{"", "2START", "HAS SPACE", "HAS=EQUALS", "LINE\nBREAK", "UNICODÉ"} {
		if validEnvName(name) {
			t.Fatalf("validEnvName() accepted invalid input")
		}
	}
}

func TestSelectKeyDownloadRequiresExplicitAvailablePrivateMaterial(t *testing.T) {
	resource := secretservice.DecryptedResource{Material: &secretservice.KeyMaterial{PEMPublic: "PUBLIC"}}
	if payload, err := selectKeyDownload(resource, "pem", false); err != nil || string(payload) != "PUBLIC" {
		t.Fatalf("default public selection = %q, %v", payload, err)
	}
	if _, err := selectKeyDownload(resource, "pem", true); err == nil {
		t.Fatal("explicit private selection silently fell back to public material")
	}
}

func TestE2EEKeyAndCertificateCommandsDecryptLocally(t *testing.T) {
	server, environment, legacyRequests := newCommandE2EEFixture(t)
	defer server.Close()
	tempDir := t.TempDir()

	run := func(arguments ...string) (string, string, int) {
		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		app := NewApp(stdout, stderr)
		app.httpClient = server.Client()
		app.envLookup = func(name string) string { return environment[name] }
		arguments = append(arguments, "--config", filepath.Join(tempDir, "missing.yaml"))
		code := app.ExecuteArgs(arguments)
		return stdout.String(), stderr.String(), code
	}

	stdout, stderr, code := run("key", "list", "--json")
	if code != exitOK || !strings.Contains(stdout, "DEPLOY_KEY") || stderr != "" {
		t.Fatalf("encrypted key list failed: code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	privatePath := filepath.Join(tempDir, "key-private.pem")
	_, stderr, code = run("key", "download", "44444444-4444-4444-8444-444444444444", "--private", "--output", privatePath)
	if payload, err := os.ReadFile(privatePath); code != exitOK || err != nil || string(payload) != "PRIVATE-KEY" || stderr != "" {
		t.Fatalf("encrypted private key download failed: code=%d error=%v stderr=%s", code, err, stderr)
	}
	publicPath := filepath.Join(tempDir, "key-public.pem")
	_, stderr, code = run("key", "download", "44444444-4444-4444-8444-444444444444", "--output", publicPath)
	if payload, err := os.ReadFile(publicPath); code != exitOK || err != nil || string(payload) != "PUBLIC-KEY" || stderr != "" {
		t.Fatalf("encrypted public key download failed: code=%d error=%v stderr=%s", code, err, stderr)
	}
	certificatePath := filepath.Join(tempDir, "certificate.pem")
	_, stderr, code = run("cert", "download", "55555555-5555-4555-8555-555555555555", "--output", certificatePath)
	if payload, err := os.ReadFile(certificatePath); code != exitOK || err != nil || string(payload) != "CERTIFICATE" || stderr != "" {
		t.Fatalf("encrypted certificate download failed: code=%d error=%v stderr=%s", code, err, stderr)
	}
	certificateKeyPath := filepath.Join(tempDir, "certificate-key.pem")
	_, stderr, code = run("cert", "download", "55555555-5555-4555-8555-555555555555", "--private-key", "--output", certificateKeyPath)
	info, statErr := os.Stat(certificateKeyPath)
	mode := os.FileMode(0)
	if info != nil {
		mode = info.Mode().Perm()
	}
	if payload, err := os.ReadFile(certificateKeyPath); code != exitOK || err != nil || string(payload) != "CERTIFICATE-PRIVATE" || stderr != "" || statErr != nil || mode != 0o600 {
		t.Fatalf("encrypted certificate private key download failed: code=%d read=%v stat=%v mode=%v stderr=%s", code, err, statErr, mode, stderr)
	}
	if legacyRequests.Load() != 0 {
		t.Fatal("encrypted resource commands attempted a legacy API request")
	}
}

func newCommandE2EEFixture(t *testing.T) (*httptest.Server, map[string]string, *atomic.Int32) {
	t.Helper()
	const (
		vaultID     = "33333333-3333-4333-8333-333333333333"
		recipientID = "11111111-1111-4111-8111-111111111111"
		secretID    = "22222222-2222-4222-8222-222222222222"
		secretName  = "PIPELINE_TOKEN"
		secretValue = "fixture-value"
		keyID       = "44444444-4444-4444-8444-444444444444"
		keyName     = "DEPLOY_KEY"
		certID      = "55555555-5555-4555-8555-555555555555"
		certName    = "TLS_CERT"
	)
	keyPair, err := secryncrypto.GenerateRecipientKeyPairWithRandom(bytes.NewReader(bytes.Repeat([]byte{0x51}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	vek := bytes.Repeat([]byte{0x52}, 32)
	recipientEnvelope, err := secryncrypto.WrapVEKForRecipientWithRandom(
		vek, keyPair.PublicKey,
		secryncrypto.RecipientContext{VaultID: vaultID, RecipientID: recipientID, KeyVersion: 1},
		bytes.NewReader(bytes.Repeat([]byte{0x53}, 56)),
	)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := json.Marshal(map[string]any{"name": secretName, "value": secretValue, "contentType": "text/plain", "tags": []string{}})
	if err != nil {
		t.Fatal(err)
	}
	resourceEnvelope, err := secryncrypto.EncryptResourceWithRandom(
		plaintext, vek,
		secryncrypto.ResourceContext{VaultID: vaultID, ResourceType: "secret", ResourceID: secretID, AADVersion: 1, KeyVersion: 1},
		bytes.NewReader(bytes.Repeat([]byte{0x54}, 80)),
	)
	if err != nil {
		t.Fatal(err)
	}
	nameIndex, err := secryncrypto.NameIndexHex(vek, vaultID, secretName)
	if err != nil {
		t.Fatal(err)
	}
	item := client.EncryptedSecret{
		ID: secretID, VaultID: vaultID, NameIndex: nameIndex, Version: 1, AADVersion: 1, KeyVersion: 1,
		Nonce: resourceEnvelope.Nonce, Ciphertext: resourceEnvelope.Ciphertext, WrappedDEK: resourceEnvelope.WrappedDEK, Enabled: true,
	}
	encryptResource := func(resourceType, id, name string, payload map[string]any, marker byte) client.EncryptedResource {
		plaintext, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		envelope, encryptErr := secryncrypto.EncryptResourceWithRandom(
			plaintext, vek,
			secryncrypto.ResourceContext{VaultID: vaultID, ResourceType: resourceType, ResourceID: id, AADVersion: 1, KeyVersion: 1},
			bytes.NewReader(bytes.Repeat([]byte{marker}, 80)),
		)
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		index, indexErr := secryncrypto.NameIndexHex(vek, vaultID, name)
		if indexErr != nil {
			t.Fatal(indexErr)
		}
		return client.EncryptedResource{ID: id, VaultID: vaultID, NameIndex: index, Version: 1, AADVersion: 1, KeyVersion: 1, Nonce: envelope.Nonce, Ciphertext: envelope.Ciphertext, WrappedDEK: envelope.WrappedDEK}
	}
	keyItem := encryptResource("key", keyID, keyName, map[string]any{
		"name": keyName, "material": map[string]any{"pemPrivate": "PRIVATE-KEY", "pemPublic": "PUBLIC-KEY"}, "keyType": "RSA", "keySize": 2048, "outputFormat": "pem",
	}, 0x55)
	certItem := encryptResource("certificate", certID, certName, map[string]any{
		"name": certName, "certificatePem": "CERTIFICATE", "privateKeyPem": "CERTIFICATE-PRIVATE",
	}, 0x56)
	legacyRequests := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.String(), secretName) || strings.Contains(r.URL.String(), secretValue) {
			t.Error("plaintext secret material was sent to the server")
		}
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			legacyRequests.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch r.URL.Path {
		case "/v2/vaults/vault-uri/crypto/envelope":
			_ = json.NewEncoder(w).Encode(client.VaultKeyEnvelope{
				Version: 1, VaultID: vaultID, RecipientID: recipientID, KeyVersion: 1,
				Algorithm: recipientEnvelope.Algorithm, EphemeralPublicKey: recipientEnvelope.EphemeralPublicKey,
				Nonce: recipientEnvelope.Nonce, Ciphertext: recipientEnvelope.Ciphertext,
			})
		case "/v2/vaults/vault-uri/secrets":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "data": []client.EncryptedSecret{item}, "meta": map[string]any{"next_cursor": nil}})
		case "/v2/vaults/vault-uri/secrets/by-index/" + nameIndex:
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "data": item})
		case "/v2/vaults/vault-uri/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "resource_type": "key", "data": []client.EncryptedResource{keyItem}, "meta": map[string]any{"next_cursor": nil}})
		case "/v2/vaults/vault-uri/keys/" + keyID:
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "resource_type": "key", "data": keyItem})
		case "/v2/vaults/vault-uri/certificates":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "resource_type": "certificate", "data": []client.EncryptedResource{certItem}, "meta": map[string]any{"next_cursor": nil}})
		case "/v2/vaults/vault-uri/certificates/" + certID:
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "resource_type": "certificate", "data": certItem})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	environment := map[string]string{
		"SECRYN_BASE_URL": server.URL, "SECRYN_VAULT_ID": "vault-uri", "SECRYN_ACCESS_KEY": "access-token",
		"SECRYN_RECIPIENT_ID":          recipientID,
		"SECRYN_RECIPIENT_PRIVATE_KEY": base64.RawURLEncoding.EncodeToString(keyPair.PrivateKey),
	}
	return server, environment, legacyRequests
}
