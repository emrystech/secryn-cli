# secryn-cli

Official command-line interface for Secryn, a self-hosted platform for managing secrets, keys, and certificates.

## Installation

### Install Script (primary)

Linux and macOS only:

```bash
curl -fsSL https://raw.githubusercontent.com/emrystech/secryn-cli/main/scripts/install.sh | bash
```

Pinned version:

```bash
curl -fsSL https://raw.githubusercontent.com/emrystech/secryn-cli/main/scripts/install.sh | bash -s -- --version v1.0.0
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
- `SECRYN_CONFIG`

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

secryn cert list
secryn cert download CERT_ID --output cert.pem

secryn auth test
secryn doctor
```

## CI/CD usage

```yaml
steps:
  - name: Install secryn
    run: curl -fsSL https://cli.secryn.io/install.sh | bash

  - name: Verify auth
    env:
      SECRYN_BASE_URL: ${{ secrets.SECRYN_BASE_URL }}
      SECRYN_VAULT_ID: ${{ secrets.SECRYN_VAULT_ID }}
      SECRYN_ACCESS_KEY: ${{ secrets.SECRYN_ACCESS_KEY }}
    run: secryn auth test --json
```

## Release Process (maintainers)

Creating and pushing a tag triggers the GitHub Actions release workflow.

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow runs GoReleaser to build archives, generate `checksums.txt`, and publish artifacts to GitHub Releases.

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
