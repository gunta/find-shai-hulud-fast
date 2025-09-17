# Agent Notes: npm-supply-scan

This document gives fast context to new agents contributing to the project.

## Mission
Deliver a fast, scriptable npm supply-chain scanner with pluggable threat profiles. The current bundled profiles are:
- `latest` – rolling collection of recent high-signal IOCs
- `shai-hulud` – full example profile replicating the September 2025 JFrog disclosures

Profiles live under `src/signatures/packs/<id>/` and are registered via `src/signatures/registry.ts`.

## Key Components
- `src/cli.ts`: argument parsing, profile selection, telemetry orchestration
- `src/signatures/`: manifest loader, profile registry, compromised package ingestion
- `src/scanner/`: worker pool, directory walker, signature matching
- `src/reporters/`: console + JSON outputs
- `src/remote.ts`: git clone helper for `--clone-url`

## Workflow Tips
1. **Profile updates**: add/change manifests in `src/signatures/packs/`, update registry metadata, and refresh documentation if user-facing.
2. **Signature changes**: prefer lower-case literals for case-insensitive string matches; remember to extend compromised package lists when adding `package` indicators.
3. **CLI options**: keep `parseArgs` pure; mutations (e.g., resolving profile aliases) happen in `main()`.
4. **Testing**: run `bun test` (once tests are added) and spot-check `bun run src/cli.ts --list-profiles` before shipping profile edits.
5. **Telemetry**: ensure long-running loops call `clearTelemetryLine()` before emitting multi-line output.

## Coding Conventions
- TypeScript, ES modules, Bun runtime
- ASCII source files by default
- Minimal but meaningful comments explaining non-obvious logic
- Logger levels: `info` for high-level flow, `debug` for verbose details, `trace` for per-match noise

## Release Checklist (WIP)
- `bun build src/cli.ts --compile --outfile=bin/npm-supply-scan`
- Smoke test binary on at least one real directory
- Update `README.md` & `PRD.md` if feature flags or profiles change
- Prepare changelog noting profile updates and new detections

For questions or TODOs, open an issue tagged with `profiles`, `cli`, or `telemetry`.
