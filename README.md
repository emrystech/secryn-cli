# secryn-cli

Official command-line interface for Secryn, a self-hosted platform for managing secrets, keys, and certificates.

## Installation

### Install Script (primary)

Linux and macOS only:

```bash
curl -fsSL https://cli.secryn.io | bash
```

Pinned version:

```bash
curl -fsSL https://cli.secryn.io | bash -s -- --version v1.0.0
```

Notes:
- The install script downloads prebuilt binaries from GitHub Releases.
- Go is **not** required on the target machine.
- The script verifies checksums when `sha256sum`, `shasum`, or `openssl` is available.

### GitHub Releases (manual fallback)

Download the correct archive for your OS/architecture from:

- [GitHub Releases](https://github.com/emrystech/secryn-cli/releases)

Then extract and place `secryn` on your `PATH`.

## Verify installation

```bash
secryn --version
```

## Configuration

```bash
secryn config set \
  --base-url https://demo.secryn.io/api \
  --vault-id VAULT_ID \
  --access-key TOKEN

secryn config show
```

Environment variable overrides:
- `SECRYN_BASE_URL`
- `SECRYN_VAULT_ID`
- `SECRYN_ACCESS_KEY`
- `SECRYN_RECIPIENT_ID` (enables E2EE together with the recipient private key)
- `SECRYN_RECIPIENT_PRIVATE_KEY` (raw 32-byte X25519 private key, unpadded Base64URL)
- `SECRYN_CONFIG`

For an E2EE vault, configure both recipient fields. The CLI fails closed when
only one is present and never uses the vault access key as encryption material.
The local config file is written with mode `0600`; its equivalent YAML fields
are `recipient_id` and `recipient_private_key`. Never commit that file.

## Commands

```bash
secryn config set --base-url https://demo.secryn.io/api --vault-id VAULT_ID --access-key TOKEN
secryn config show

secryn secret list
secryn secret list --names-only
secryn secret get DB_PASSWORD
secryn secret get DB_PASSWORD --json

secryn env pull > .env

secryn key list
secryn key download KEY_ID --output key.pem
secryn key download KEY_ID --private --output private-key.pem

secryn cert list
secryn cert download CERT_ID --output cert.pem

secryn auth test
secryn mcp serve
secryn doctor
secryn update --check
secryn update
```

For E2EE vaults, `key download` returns public material by default. Use
`--private` only when private key material is explicitly required. Certificate
downloads likewise require `--private-key` to emit their private key. Private
outputs are atomically replaced as regular files with mode `0600`, including
when the destination previously existed or was a symbolic link.

`secryn update` installs the latest GitHub release in place after verifying its
published SHA-256 checksum. Use `secryn update --version v1.0.1` to install a
specific release, or add `--json` for machine-readable output.

## CI/CD usage

```yaml
steps:
  - name: Install secryn
    run: curl -fsSL https://raw.githubusercontent.com/emrystech/secryn-cli/main/scripts/install.sh | bash

  - name: Verify auth
    env:
      SECRYN_BASE_URL: ${{ secrets.SECRYN_BASE_URL }}
      SECRYN_VAULT_ID: ${{ secrets.SECRYN_VAULT_ID }}
      SECRYN_ACCESS_KEY: ${{ secrets.SECRYN_ACCESS_KEY }}
      SECRYN_RECIPIENT_ID: ${{ secrets.SECRYN_RECIPIENT_ID }}
      SECRYN_RECIPIENT_PRIVATE_KEY: ${{ secrets.SECRYN_RECIPIENT_PRIVATE_KEY }}
    run: secryn auth test --json

  - name: Pull encrypted environment
    env:
      SECRYN_BASE_URL: ${{ secrets.SECRYN_BASE_URL }}
      SECRYN_VAULT_ID: ${{ secrets.SECRYN_VAULT_ID }}
      SECRYN_ACCESS_KEY: ${{ secrets.SECRYN_ACCESS_KEY }}
      SECRYN_RECIPIENT_ID: ${{ secrets.SECRYN_RECIPIENT_ID }}
      SECRYN_RECIPIENT_PRIVATE_KEY: ${{ secrets.SECRYN_RECIPIENT_PRIVATE_KEY }}
    run: secryn env pull > "$RUNNER_TEMP/secryn.env"
```

For E2EE vaults, ciphertext is retrieved with the access key and decrypted only
inside the CLI process using the recipient private key. Treat the generated
`.env` file as plaintext and delete it after use. List-based commands fail
closed if a vault contains more than 10,000 active secrets; this explicit
capacity limit prevents unbounded memory use in automation.

## Local MCP server

`secryn mcp serve` exposes the configured E2EE vault to a trusted local MCP
host over stdin/stdout. It does not open a network listener and never calls a
plaintext MCP endpoint on the Secryn server. The access key authenticates
ciphertext retrieval; the CLI decrypts returned envelopes locally with the
configured recipient identity.

Example host configuration using the secure CLI config file:

```json
{
  "mcpServers": {
    "secryn": {
      "command": "secryn",
      "args": ["mcp", "serve"],
      "env": {
        "SECRYN_CONFIG": "/absolute/path/to/secryn/config.yaml"
      }
    }
  }
}
```

The server provides six read-only tools:

- `secryn_secret_list` returns names and update timestamps, never values.
- `secryn_secret_get` returns one exact-name secret, including its plaintext
  value, as the explicitly requested tool result.
- `secryn_key_list` and `secryn_certificate_list` return names and update
  timestamps without material.
- `secryn_key_get` returns public PEM or OpenSSH material by default;
  `include_private: true` is required to request private key material.
- `secryn_certificate_get` returns the certificate by default;
  `include_private: true` is required to include its private key.

The stdio transport supports the legacy initialize handshake through MCP
`2025-11-25`. It also supports MCP `2026-07-28` discovery and direct tool
requests. Modern requests must carry that protocol version and client
capabilities in `_meta`; the connection is pinned to the first protocol era
and rejects legacy/modern mixing.

MCP stdout contains protocol frames only; diagnostics go to stderr. The server
refuses legacy, partially configured, pending-bootstrap, and unknown encryption
modes. MCP tool results containing a secret value, private key, or certificate
are plaintext inside the trusted host process, so do not enable this server for
an untrusted host or forward its stdio transport remotely.

## Release Process (maintainers)

Creating and pushing a tag triggers the GitHub Actions release workflow.

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow runs GoReleaser to build archives, generate `checksums.txt`, and publish artifacts to GitHub Releases.

For a pinned, auditable manual install, download the versioned archive and its
published checksum, then verify the archive before extracting it:

```bash
curl -fsSLo secryn_linux_amd64.tar.gz https://github.com/emrystech/secryn-cli/releases/download/v1.0.0/secryn_linux_amd64.tar.gz
curl -fsSLo checksums.txt https://github.com/emrystech/secryn-cli/releases/download/v1.0.0/checksums.txt
grep 'secryn_linux_amd64.tar.gz' checksums.txt | sha256sum -c -
tar --no-same-owner -xzf secryn_linux_amd64.tar.gz
sudo install -m 0755 secryn /usr/local/bin/secryn
```

## Exit codes

- `0`: success
- `1`: generic runtime/API error
- `2`: usage/config error
- `3`: authentication/authorization failure (`401/403`)
- `4`: not found/gone (`404/410`)

## Development

```bash
make tidy
make fmt
make test
make lint
make release-check
make snapshot
```

## License

MIT. See [LICENSE](LICENSE).
