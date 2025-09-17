# npm-supply-scan PRD

## 1. Overview
- **Product Name**: npm-supply-scan (codename "Sandtrout")
- **Prepared By**: Codex AI (collaborating with stakeholder)
- **Date**: 2025-09-16 (update as needed)
- **Status**: Draft v2.0

## 2. Background & Problem Statement
High-impact npm supply-chain attacks continue to surface (e.g., the September 2025 "shai hulud" incident, recurring Telegram/Discord credential stealers, typosquats targeting CI workloads). Teams struggle to sweep workstations, build agents, and cached dependencies quickly when a new advisory drops. Security desks need a fast, scriptable scanner that can ship updated IOCs rapidly and plug into automation.

Manual greps or ad-hoc scripts are brittle: lockfile formats change, malicious packages ship obfuscated payloads, and hunting across caches is tedious. A purpose-built scanner with curated threat profiles reduces the mean-time-to-detect across fleets.

## 3. Goals & Non-Goals
### Goals
1. Detect known npm supply-chain indicators of compromise (IOCs) across workstations, CI agents, and source repositories.
2. Ship with multiple threat profiles (e.g., rolling "latest", shai hulud) and support custom manifests.
3. Provide high-throughput scanning with Bun workers and live telemetry suitable for large monorepos and caches.
4. Offer actionable reporting: color console output, JSON for CI, remediation hints for operators.
5. Package as a self-contained binary (Bun compile) with a path to npm/Homebrew distribution.

### Non-Goals
- Automated removal/quarantine (detection-first release).
- Coverage of non-JavaScript/Node ecosystems beyond best-effort file scanning.
- Guaranteed zero false negatives; heuristics supplement curated signatures but do not replace EDR coverage.

## 4. Target Users & Use Cases
- **Security Engineers / Incident Responders**: Sweep developer laptops and jump boxes when new advisories land.
- **DevOps / SRE**: Gate CI/CD pipelines by scanning checkouts before builds.
- **Developers**: Self-service verification of local workspaces and caches.
- **IT Administrators**: Fleet automation via MDM or remote management tooling.

Journeys:
1. Security team broadcasts "Run `npm-supply-scan latest --default-paths`" after a new advisory; developers respond quickly.
2. CI job runs `npm-supply-scan shai . --json` and fails build on detections.
3. IR analyst uses `npm-supply-scan --clone-url <repo>` to inspect a suspect open-source project offline.

## 5. Scope & Features
### 5.1 Threat Profiles & Signatures
- Registry-driven profile catalog (`src/signatures/registry.ts`).
- Each profile defines a manifest (`pack.json`) with metadata, extends chain, signatures, and optional compromised package list.
- Bundled profiles:
  - `latest`: Rolling collection of high-signal IOCs for the last 12 months (extends `shai-hulud`, adds Telegram/Discord heuristics, curated compromised package slice).
  - `shai-hulud`: Complete pack of indicators released by JFrog for the September 2025 attack.
- Future profiles (roadmap): Crypto wallet stealers, CI-focused backdoors, typosquat families.

### 5.2 Detection Capabilities
- Indicators supported: filename globs, literal strings, case-insensitive regex, SHA-256 hashes, compromised package versions from lockfiles.
- Signature loader builds regex/glob caches and auto-injects lockfile globs for compromised package lists.
- Optional heuristics (e.g., Telegram Bot API, Discord webhook exfiltration, obfuscated PowerShell launchers).

### 5.3 Scan Targets
- Local directories (positional args or `--path`). Default roots include user home directories, npm/pnpm/yarn/bun caches, common workspace folders.
- Remote Git repositories via `--clone-url` and optional `--clone-branch`; temporary clone cleaned up unless `--keep-temp` set.
- Lockfiles (`package-lock.json`, `pnpm-lock.yaml`, etc.), caches, vendored modules.

### 5.4 Performance & Telemetry
- Worker pool sized to `min(max(2, cores - 1), 32)` with queue backpressure; optional `--threads` override.
- Chunked reads when files exceed `maxBytes` threshold (default 5 MB) unless forced full read (lockfiles, etc.).
- Telemetry (enabled when stdout is TTY): files scanned, detections, throughput, CPU %, queue depth, worker utilisation, error count.
- Environment controls: `NPM_SUPPLY_SCAN_PROFILE`, `NPM_SUPPLY_SCAN_LOG_LEVEL`, `NPM_SUPPLY_SCAN_TICK`.

### 5.5 Reporting & UX
- Console reporter with severity colouring, detection table, profile metadata summary.
- JSON reporter includes full detection payload, error list, and profile summary for downstream systems.
- Interactive remediation prompt with checklist when detections occur (TTY only).

### 5.6 Packaging & Distribution
- Bun compile to produce single binaries (macOS & Linux, `x64`/`arm64`).
- npm package wraps binary (planned), Homebrew tap (planned), Docker image (stretch).
- Release automation to publish checksums and signed artifacts (roadmap).

### 5.7 Configuration & Extensibility
- CLI flags: `--profile`, `--list-profiles`, `--default-paths`, `--path`, `--exclude`, `--threads`, `--max-depth`, `--clone-url`, `--clone-branch`, `--keep-temp`, `--signature-file`, `--json`, `--no-metrics`, `--log-level`.
- Config file support deferred (was `.shai-scan.toml`; now roadmap item).
- Custom profiles loaded via `--signature-file` pointing to manifest JSON.

## 6. Success Metrics
- Scan ≥1M files in <3 minutes on an 8-core Apple Silicon laptop (with SSD cache warm).
- Telemetry overhead <5% CPU compared to telemetry-disabled runs.
- False positive rate <1% on curated clean dataset; ability to suppress via `--exclude`.
- Binary size ≤30 MB compressed.
- CI adoption: ability to integrate in <10 lines of YAML for GitHub Actions.

## 7. Assumptions & Dependencies
- Bun ≥1.1.9 available on target machines.
- Git CLI accessible for remote clone feature.
- Users responsible for credentials when scanning private repos (token env vars, `git` credential store, etc.).
- Signature content maintained manually until automated feeds are wired up.

## 8. Risks & Mitigations
- **IO saturation on network shares**: allow path filtering, document best practices, consider throttling env var.
- **Rapidly evolving threats**: emphasise extensible profile system and document update workflow.
- **False positives**: include contextual metadata, provide remediation prompts, document review steps.
- **Privilege limitations**: surface permission errors clearly, exit code `1` when partial failures occur.
- **Supply-chain trust**: plan signed releases, checksums, reproducible builds in roadmap.

## 9. Milestones (Tentative)
1. **M1**: Core walker, worker pool, signature loader refactor (complete).
2. **M2**: Threat profile registry + latest bundle + CLI UX refresh (complete).
3. **M3**: Packaging prep (binary build scripts, release automation, docs).
4. **M4**: Additional profiles, CI templates, signature update cadence.

## 10. Future Enhancements
- Remote profile fetching (signed manifests, ETag caching).
- Ignore list / allowlist configuration.
- Archive inspection (`.tgz`, `.zip`) for cached package tarballs.
- Integration hooks for SIEM/SOAR (webhooks, syslog, OpenTelemetry).
- Optional auto-remediation hooks (quarantine scripts) with explicit opt-in.

## 11. Open Questions
- Preferred distribution cadence for profile updates (weekly vs on-demand)?
- Who curates `latest` profile updates—central security team, OSS contributors, automation?
- How do we communicate updates? RSS feed? npm package patch releases?
- Should we support Windows Defender / EDR integration (exit code conventions, event logs)?

## 12. Appendix: Reference IOC Sources
- JFrog Research: [Shai Hulud npm supply-chain attack](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/)
- GitHub Security Lab advisories on npm credential stealers (Telegram/Discord campaigns).
- Checkmarx blog coverage of typosquat families targeting Roblox/crypto ecosystems.
- npm Security advisories feed for compromised package disclosures.

