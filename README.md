# npm-supply-scan

Ultra-fast Bun-powered scanner for npm supply-chain threats. The CLI ships with curated threat profiles, including a rolling "latest" bundle and the original shai hulud fast scanner profile as a worked example.

> ⚠️ **Security note:** Review detections before taking action and follow your organisation's incident-response process.

## Highlights
- 🚄 Parallel filesystem walker with Bun workers for multi-GB/minute throughput
- 🧩 Pluggable threat profiles (`latest`, `shai-hulud`, custom JSON manifests)
- 🗃️ Built-in registry of compromised package versions and file-level IOCs
- 🛡️ Detection output maps matches back to the referenced threat campaigns for rapid triage
- 🌐 Remote repository scanning (clone → scan → optionally cleanup)
- 📊 Live telemetry (files/sec, MB/sec, CPU, worker queue depth)
- 📟 Console reporter plus structured JSON output for CI pipelines

## Quick Start
```bash
# Install dependencies and build a standalone binary
bun install
bun build ./src/cli.ts --compile --outfile=bin/npm-supply-scan

# Scan default npm/pnpm/yarn/bun caches with the rolling profile
bin/npm-supply-scan --default-paths

# Run the shai hulud profile against a specific project directory
bin/npm-supply-scan shai ./demo/project

# List the bundled profiles and metadata
bin/npm-supply-scan --list-profiles

# Emit JSON for CI aggregation
bin/npm-supply-scan latest ./monorepo --json > report.json
```

## Installation Options
- **Bun binary (local build)** – `bun build src/cli.ts --compile --outfile bin/npm-supply-scan`
- **npm package (planned)** – publishes the compiled binary with a thin wrapper
- **Homebrew tap (planned)** – Homebrew formula pinned to GitHub releases

## Configuration
- Threat profiles live in `src/signatures/profiles.json`. Add or edit entries there to register new packs, update metadata, or change the default profile without touching TypeScript.
- Scanner defaults (e.g., lockfile globs) are sourced from `src/signatures/config.json`. Adjust these values to fine-tune which paths are inspected during package matching.
- Runtime JSON data is read once and cached in memory for faster scans; remember to restart the CLI when editing configuration files.

## Release Workflow
- Run `bun run release:dry-run` to preview version bumps, changelog entries, and artifact steps without modifying the repository.
- Run `bun run release` for a full release: tests + lint, cross-platform binary builds, npm packing via `bun pm pack`, GitHub Release asset uploads, and Homebrew formula generation.
- Provide `GITHUB_TOKEN` and `BUN_AUTH_TOKEN`/`NPM_TOKEN` in the environment so the automation can publish to GitHub Releases and npm.

## Threat Profiles
Profiles live under `src/signatures/packs/` and are registered via `src/signatures/profiles.json` (loaded by the runtime registry).

- `latest` (default): Rolling bundle that extends other packs and aggregates high-signal IOCs from the last 12 months. Metadata lives in `packs/latest/threats.json` and its compromised packages list lives in `packs/latest/latest-compromised-packages.json`.
- `shai-hulud`: Full fast scanner profile for the September 2025 shai hulud attack. Pack manifest and package list live in `packs/shai-hulud/`.

Each pack manifest:
- Can extend other packs using `extends`
- Can reference a `compromisedPackagesFile` (lockfile indicators auto-generated)
- Defines `signatures` with `glob`, `regex`, `string`, `sha256`, and `package` indicators

Use `--profile <id>` or prefix the profile (`npm-supply-scan shai ./path`) to switch. Custom manifests can be loaded via `--signature-file <path>`.

## CLI Reference
```
Usage: npm-supply-scan [profile] [options] [paths...]

Options:
  --profile <id>          Pick a threat profile (see --list-profiles)
  --list-profiles         Show bundled threat profiles and exit
  --default-paths         Include standard npm/pnpm/yarn/bun caches
  --path <dir>            Additional directory to scan (repeatable)
  --exclude <pattern>     Substring filter to skip paths (repeatable)
  --threads <n>           Override automatic worker count
  --max-depth <n>         Limit directory traversal depth
  --clone-url <url>       Clone and scan remote Git repository
  --clone-branch <ref>    Checkout specific ref for remote scan
  --keep-temp             Keep cloned repository directory
  --signature-file <p>    Load custom IOC signature manifest
  --json                  Emit JSON report instead of console summary
  --no-metrics            Disable live telemetry output
  --log-level <level>     Log level (silent|info|debug|trace)
  --help                  Show this help message
  --version               Show version
```
> Tip: the first positional argument will be treated as a profile if it matches a known profile name/alias and no path of that name exists. Prefix paths with `./` to disambiguate.

### JSON Output Shape
```
{
  "scannedFiles": 12345,
  "bytesScanned": 987654321,
  "durationMs": 5123,
  "detections": [...],
  "errors": [...],
  "signatureSummary": {
    "profileId": "latest",
    "title": "Latest npm supply-chain threats (rolling)",
    "updated": "2025-09-16",
    "sources": ["https://jfrog.com/blog/..."],
    "resolvedProfiles": ["latest", "shai-hulud"]
  },
  "generatedAt": "2025-09-16T12:34:56.789Z"
}
```

## Telemetry & Performance
- Worker count defaults to `min(max(2, cores-1), 32)`; override via `--threads`
- Environment knobs:
  - `NPM_SUPPLY_SCAN_PROFILE` – default profile ID/alias
  - `NPM_SUPPLY_SCAN_LOG_LEVEL` – default log verbosity
  - `NPM_SUPPLY_SCAN_TICK` – telemetry refresh interval (ms)
- Telemetry renders files/sec, MB/sec, CPU %, queue depth, busy workers, and error count in-place

## Development
```bash
bun install
bun run dev -- --profile latest --default-paths
bun test
bunx eslint .
```

### Updating or Adding Profiles
1. Create a new directory under `src/signatures/packs/<profile-id>/`.
2. Add a `pack.json` manifest describing signatures and metadata.
3. Optional: add supporting JSON (e.g., `compromised-packages.json`, `threats.json`).
4. Register the profile in `src/signatures/registry.ts` (with aliases, summary, etc.).
5. Run the scanner against representative fixtures before publishing.

## Roadmap
- [ ] Additional bundled profiles (crypto stealers, typosquats, CI backdoors)
- [ ] Subscription/update channel for profile manifests
- [ ] CI templates for GitHub Actions and GitLab CI
- [ ] Signed release artifacts and npm distribution
- [ ] Integration tests covering remote clone flow and heuristics

## Responsible Use
- Run in read-only contexts; the scanner never modifies target files
- Validate detections with your security team prior to remediation
- Verify release artifacts/signatures before deploying widely

## License
TBD (recommended: Apache-2.0 or MIT)
