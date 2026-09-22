# Agent guide

`fnb` is a read-only Go CLI for a view-only secondary user of FNB South Africa Online Banking. The approved architecture and milestone boundaries are in [`docs/plan.md`](docs/plan.md).

## Repository structure

- `cmd/fnb`: process entry point
- `internal/cli`: Cobra command tree, flags, error reporting and version wiring
- `internal/config`: XDG paths, TOML configuration and identity validation
- `internal/exitcode`: coded errors and exit status constants
- `internal/output`: JSON, plain and table rendering
- `internal/secure`: pinned-directory secure writes and scrubbed child environments
- `docs`: approved design, threat model, incident procedure and provenance

## Commands

- `make build`: build `fnb` with the version from `version.env`
- `make test`: run all Go tests
- `make lint`: run `go vet` and verify `gofmt`
- `make vet`: run `go vet`
- `make fmt`: format Go files
- `make tidy`: update module metadata
- `make clean`: remove the local binary

Run `make lint test` and `go build ./...` before finishing a change.

## Rules

- Preserve the read-only boundary. Do not add payment, transfer, beneficiary, profile or settings mutations.
- Do not add network behavior outside the milestone approved in `docs/plan.md`.
- Do not use the `bitshiftza/fnb-api` source as an implementation reference. Work only from approved repository documentation and synthetic fixtures.
- Do not add comments or doc comments to Go source. The only exceptions are required build tags and generated-code markers.
- Never log secrets, pass them as flags or expose them to child processes.
- Keep dependencies limited to Cobra, BurntSushi TOML and `golang.org/x/sys` until the approved plan explicitly expands them.
