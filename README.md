# Homelab Doctor

Homelab Doctor is an open-source, read-only Linux diagnostics CLI for self-hosters. It identifies likely configuration and health problems and creates privacy-redacted support bundles. It never cleans up resources, restarts services, changes permissions, modifies firewalls, uploads data, or performs repair actions.

## Install

```sh
go install github.com/homelab-doctor/homelab-doctor/cmd/homelab-doctor@latest
# or review and run the release installer
curl -fsSL https://raw.githubusercontent.com/homelab-doctor/homelab-doctor/main/scripts/install.sh | sh
```

Linux amd64 and arm64 release archives are produced with GoReleaser.

## Usage

```sh
homelab-doctor check
homelab-doctor check --profile docker --format json
homelab-doctor check --profile storage --format markdown
homelab-doctor check --profile networking --tcp-probe 127.0.0.1:8080
homelab-doctor bundle --output diagnostics.tar.gz --privacy private-ips
homelab-doctor explain docker.restart_loop
homelab-doctor list-checks
```

Every command accepts `--dry-run`; current commands already have no mutating behavior. Permission-limited checks are explicitly reported as `skipped`, never treated as a clean result. Public-IP lookups are disabled and no bundle is uploaded.

## Output and privacy

`check` renders terminal output by default and supports `--format json` and `--format markdown`. Findings have stable IDs, severity, evidence, an explanation, and safe remediation guidance. Bundles include redacted `report.json`, `report.md`, and a `manifest.json` containing SHA-256 hashes. Archive members are generated-only, names are validated, and symlink output paths are refused.

Secrets shaped as passwords, tokens, API keys, cookies, and Authorization values are masked. `--privacy private-ips` also masks RFC1918 IPv4 addresses. Redaction is deliberately conservative, so review a bundle before sharing it.

## Development

```sh
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
go build ./...
git diff --check
```

See [docs/check-writing.md](docs/check-writing.md), [SECURITY.md](SECURITY.md), and [CONTRIBUTING.md](CONTRIBUTING.md). The report contract is in [schemas/report.schema.json](schemas/report.schema.json); example outputs are in [examples](examples).
