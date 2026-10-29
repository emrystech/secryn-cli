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

secryn run -- npm run deploy
secryn run --only DB_PASSWORD,API_TOKEN -- python migrate.py

secryn key list
secryn key download KEY_ID --output key.pem

secryn cert list
secryn cert download CERT_ID --output cert.pem

secryn auth test
secryn doctor
secryn update --check
secryn update
```

`secryn update` installs the latest GitHub release in place after verifying its
published SHA-256 checksum. Use `secryn update --version v1.0.1` to install a
specific release, or add `--json` for machine-readable output.

## Run a command with secrets

`secryn run` loads the vault with the same config, flags, and `SECRYN_*` variables as the other commands, then starts a process with those secrets in its environment. Values are passed only to that process. They are not written to stdout, stderr, or logs, so an agent can run a tool without taking the secret into its own context.

```bash
secryn run -- npm run deploy
secryn run --only DB_PASSWORD,API_TOKEN -- python migrate.py --dry-run
secryn run --preserve-env -- ./deploy.sh
```

Put `--` before the command when the command has its own flags.

When a name exists in both the environment and the vault, the vault value wins, including names such as `PATH`. `--preserve-env` keeps variables that are already set (even when empty) and fills in only the missing names.

`SECRYN_ACCESS_KEY` is removed from the child environment. `--inherit-access-key` passes it through.

`--only` injects the listed secrets and fails if any name is missing. Other secret names that are not valid environment variables (for example `my-secret`) are skipped with a warning. The command is not started if authentication fails or the vault cannot be reached.

On Linux and macOS, secryn replaces itself with the command. Signals such as Ctrl-C and SIGTERM go straight to that command, and the shell sees its exit code. On Windows, secryn stays running long enough to forward those signals and then exits with the command's status. Output is not masked: if the command prints a secret, that output is visible.

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
    run: secryn auth test --json
```

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

`secryn run` uses those codes when the command never starts. After the command starts, secryn exits with that command's status.

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
