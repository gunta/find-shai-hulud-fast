# Shai Hulud Scanner

Fast, parallel Bun-powered scanner for detecting the "shai hulud" npm supply-chain malware across local file systems and remote Git repositories.

> ⚠️ **Security note:** This project focuses on detection. Always review findings before taking action and follow your organization's incident-response procedures.

## Features
- 🚄 Ultra-fast multi-core scanning optimized with Bun workers
- 🔍 Detects known shai hulud IOCs in local directories, npm/pnpm/yarn/bun caches, and cloned repos
- 🌐 Remote GitHub repository scanning (auto-clone, inspect, clean up)
- 📊 Live telemetry: files/sec, MB/sec, CPU usage, worker activity
- 🎨 Color-rich terminal UX plus optional JSON reporting
- 📦 Distributable as Bun-compiled binary, npm CLI, and Homebrew formula

## Installation
The tool can be consumed in multiple ways. Pick the option that fits your workflow.

### 1. Bun Binary
```bash
bun install
bun build ./src/cli.ts --compile --outfile=bin/shai-scan
./bin/shai-scan --help
```
A release pipeline will publish prebuilt binaries per platform (macOS/Linux, `x64` & `arm64`).

### 2. npm Package (planned)
```bash
npm install -g @sandtrout/shai-hulud-scanner
shai-scan --help
```
The npm package bundles the Bun binary (or downloads the correct build during postinstall).

### 3. Homebrew Tap (planned)
```bash
brew tap sandtrout/homebrew-tap
brew install shai-scan
```
Formula will reference GitHub releases and verify checksums.

## Quick Start
Scan your home directory and common package-manager caches:
```bash
shai-scan --default-paths
```
Scan specific paths concurrently:
```bash
shai-scan --path ~/projects --path ~/.npm --path ~/.bun/install/cache
```
Scan a remote GitHub repo without keeping the clone:
```bash
shai-scan --clone-url https://github.com/example/project.git
```
Generate a JSON report for CI consumption:
```bash
shai-scan . --json > report.json
```

## CLI Reference (draft)
```
Usage: shai-scan [options] [paths...]

Options:
  --default-paths        Include standard npm/pnpm/yarn/bun caches
  --path <dir>           Additional directory to scan (repeatable)
  --exclude <pattern>    Glob pattern to exclude (repeatable)
  --threads <n>          Override automatic worker count
  --max-depth <n>        Limit directory traversal depth
  --clone-url <url>      Clone and scan remote Git repo
  --clone-branch <ref>   Checkout specific branch/tag for remote scans
  --keep-temp            Keep cloned repository for later review
  --json                 Emit JSON report to stdout
  --signature-file <p>   Load custom IOC signature file (JSON)
  --no-metrics           Disable live telemetry output
  --log-level <level>    Set log verbosity (silent, info, debug)
  --help                 Show help
  --version              Show version
```

## Detection Strategy
- Signature-based matching of known filenames, hashes, code snippets, and network indicators tied to the shai hulud campaign
- Heuristics to flag suspicious postinstall scripts, credential harvesting patterns, and obfuscated payloads
- Extensible signature packs defined as JSON descriptors (hashes, globs, regex, string matches)

## Performance Notes
- Uses Bun's worker threads and async filesystem primitives to maximize throughput
- Adaptive scheduler monitors queue depth and CPU saturation, adjusting worker counts automatically
- Telemetry loop samples metrics every 500ms with minimal overhead

## Architecture Overview
- `src/cli.ts`: argument parsing, logging configuration, telemetry orchestrator
- `src/scanner/`: worker pool, directory walker, signature engine, remote repo module
- `src/signatures/`: IOC catalog plus loader for custom packs
- `src/reporters/`: terminal renderer, JSON emitter, interactive remediation prompts
- `src/utils/`: CPU/memory sampling, rate limiting, path resolution helpers

## Development
```bash
bun install
bun test
bun run lint
bun run dev -- --path .
```
Planned scripts:
- `test`: unit and integration tests (signature engine, walker, remote clone mock)
- `lint`: ESLint + TypeScript checks (using bunx)
- `dev`: run CLI with live reload for local debugging

### Updating Signatures
Edit `signatures/shai-hulud.json` with new indicators. Keep entries annotated with source and timestamp. Consider verifying hashes with multiple threat intel feeds before merging.

## Roadmap
- [ ] Core filesystem scanning with signatures & heuristics
- [ ] Remote Git clone module with cleanup
- [ ] Live telemetry and stats renderer
- [ ] JSON report output
- [ ] Package distribution pipeline (Bun compile, npm publish, Homebrew formula)
- [ ] Integration tests and CI templates

## Security & Responsible Use
- Run in read-only mode where possible; the scanner never modifies target files.
- Review detections and engage security teams before deleting packages.
- Verify signed release artifacts when downloading binaries.

## License
TBD (recommendation: Apache-2.0 or MIT).

