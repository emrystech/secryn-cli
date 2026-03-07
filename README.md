# secryn-cli

Official command-line interface for Secryn, a self-hosted platform for managing secrets, keys, and certificates.

## Features

- Single-binary Go CLI built with Cobra
- Config file in user config directory (default: `~/.config/secryn/config.yaml` on Linux/macOS)
- Config override order: flags > environment variables > config file
- JSON output support (`--json`) for automation and CI/CD
- Clean API error handling with actionable messages for `401`, `403`, `404`, and `410`
- Extensible command architecture for future commands like `backup create`, `backup restore`, `mcp test`

## Install

### From source

```bash
go install github.com/secryn/secryn-cli@latest
```

### Build locally

```bash
make tidy
make build
```

Binary output: `bin/secryn`

## Configuration

Set local config:

```bash
secryn config set \
  --base-url https://demo.secryn.io/api \
  --vault-id VAULT_ID \
  --access-key TOKEN
```

Show effective config:

```bash
secryn config show
```

Environment variable overrides:

- `SECRYN_BASE_URL`
- `SECRYN_VAULT_ID`
- `SECRYN_ACCESS_KEY`
- `SECRYN_CONFIG` (optional config file path)

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

## Automation / CI/CD examples

List secret names as JSON:

```bash
secryn secret list --names-only --json
```

Validate auth in a pipeline:

```bash
secryn auth test --json
```

Pull `.env` file during deployment:

```bash
secryn env pull > .env
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
make lint
make test
```

## Security

- This repository contains only open-source CLI client code.
- Do not commit access keys or generated secret files.
- The CLI stores local config with restricted file permissions when possible.

## License

MIT. See [LICENSE](LICENSE).
