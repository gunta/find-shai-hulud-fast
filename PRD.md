# Shai Hulud Scanner PRD

## 1. Overview
- **Product Name**: Shai Hulud Scanner (codename "Sandtrout")
- **Prepared By**: Codex AI (in collaboration with stakeholder)
- **Date**: 2024-?? (update as needed)
- **Status**: Draft v1.0

## 2. Background & Problem Statement
Recent npm ecosystem supply-chain incidents (notably the "shai hulud" campaign reported September 2024) have weaponized trusted packages and compromised developer machines. Malicious packages such as `shai-hulud`, `node-stealer`, and copycat variants injected credential stealers and backdoors by abusing postinstall hooks and obfuscated payloads. These packages frequently hide in:
- Local `node_modules` folders (npm, pnpm, yarn, bun)
- Global install directories (e.g., `~/.npm`, `/usr/local/lib/node_modules`)
- CI/CD caches and mirrors
- Source control repositories via vendored dependencies

Manual detection is slow and unreliable due to the campaign's polymorphic nature (randomized file names, nested archives, obfuscated scripts). Teams need a fast, automated scanner that can sweep local environments and remote repositories, provide actionable guidance, and integrate into CI, incident response, and developer workstations.

## 3. Goals & Non-Goals
### Goals
1. Rapidly detect known "shai hulud" indicators of compromise (IOCs) across local filesystems and remote Git repositories.
2. Deliver high-throughput scanning (multi-core, adaptive IO scheduling) without saturating system resources.
3. Provide human-readable, colorized terminal output with real-time metrics (files/sec, MB/sec, CPU %, active workers).
4. Offer remediation prompts when indicators are found (e.g., quarantine instructions, npm uninstall guidance).
5. Package distribution via Bun single-file binary, npm package, and Homebrew formula.

### Non-Goals
- Replacing endpoint security suites; focus remains on detection, not automatic isolation/removal.
- Guaranteeing zero false negatives; signature-based with limited heuristic alerts.
- Supporting non-JavaScript ecosystems beyond basic file scanning (e.g., Python, Ruby) in v1.

## 4. Target Users & Use Cases
- **Security Engineers**: Incident response sweeps of developer laptops and build servers.
- **DevOps/SRE**: CI/CD pipeline validation of cloned repositories before execution.
- **Developers**: Self-service check of local workspaces and caches.
- **IT Administrators**: Fleet-wide scripts deployed via MDM or remote management.

Typical user journeys:
1. Developer runs `bun run shai-scan .` to validate project after hearing about campaign.
2. Security team clones suspect GitHub repository via scanner to inspect dependencies.
3. CI job downloads Bun binary, scans workspace, fails build if malicious files detected.

## 5. Scope & Features
### 5.1 Core Detection
- IOC catalog: file hashes, known filenames (`shai-hulud.js`, `postinstall.js` patterns), suspicious URLs, base64 payload fragments, `exec`/`powershell` strings.
- Configurable signature packs (JSON) shipped with tool; updateable via remote fetch (Phase 2).
- File content scanning using streaming pattern matching (avoid loading whole file when possible).
- Support archives (`.tgz`, `.zip`) commonly found in npm cache (future stretch goal; optional in v1 if time allows).

### 5.2 Scan Targets
- **Local Paths**: default search roots include `~/`, `/usr/local/lib/node_modules`, `~/.npm`, `~/.cache/pnpm`, `~/.bun/install/cache`, workspace directories. Users can supply explicit paths.
- **Remote Git Repos**: clone to temp directory, scan, delete after completion. Support GitHub HTTPS URLs (public); optionally private with token env var.
- **Package Manager Caches**: detect environment-specific directories (npm, pnpm, bun, yarn) via heuristics.

### 5.3 Performance & Parallelism
- Utilize Bun's native Worker API and `Bun.spawn` for async IO.
- Auto-tune worker pool based on CPU cores and FS latency (dynamic feedback loop).
- Batching file reads, using memory-mapped or stream-based scanning.
- Progress telemetry: per-second snapshot of total files scanned, throughput (files/sec, MB/sec), CPU usage (per `os.loadavg()` / `/proc/stat` when available), active workers, queue depth.
- Minimal overhead telemetry loop (detached timer running at 500-1000ms).

### 5.4 Reporting & UX
- Colorized console output (ANSI) with severity levels.
- Summary table at end (clean vs infected, directories skipped, errors).
- Optional JSON report output for CI integration.
- Interactive prompt when detections found: suggest deletion, provide manual steps, optionally open knowledge base link.

### 5.5 Packaging & Distribution
- Build via `bun build --compile` to produce native binaries (macOS/Linux amd64 + arm64).
- Provide npm package with CLI entry pointing to Bun binary (postinstall download or include). Ensure supply-chain safety (signed checksums).
- Homebrew tap formula referencing GitHub releases (future automation script).
- Provide Dockerfile for containerized usage (stretch).

### 5.6 Configuration
- CLI flags: `--path`, `--exclude`, `--max-depth`, `--threads`, `--json`, `--no-metrics`, `--signature-file`, `--clone-url`, `--clone-branch`, `--keep-temp`, `--log-level`.
- Configuration file (`.shai-scan.toml`) for repeated runs.
- Environment variables (e.g., `SHAI_SCAN_THREADS`, `SHAI_SCAN_TOKEN`).

## 6. Success Metrics
- Scan 1M files under 3 minutes on 8-core Apple Silicon dev machine.
- <5% CPU load overhead for telemetry loop relative to scanning baseline.
- False positive rate <1% on curated clean dataset.
- Binary size ≤ 30 MB compressed for distribution.
- End-to-end remote repo scan (clone + scan) 2x faster than existing bash scripts.

## 7. Assumptions & Dependencies
- Bun v1.1+ available on target systems.
- Users can supply Git credentials/tokens when required.
- Access rights to scan directories provided (may need sudo for global node_modules).
- Signatures maintained manually initially; future automation TBD.

## 8. Risks & Mitigations
- **High IO load**: Implement rate limiting, respect `--max-bytes-per-second` (stretch) and skip large binary files by default.
- **Evasion via obfuscation**: Provide heuristic checks (suspicious command strings, encoded payloads).
- **False positives**: Offer `--exclude` and allow partial ignore list; document review process.
- **Privilege requirements**: Document need for elevated permissions; fail gracefully when lacking access.
- **Supply-chain trust**: Host releases on signed GitHub releases, provide checksums, encourage verifying signature before running.

## 9. Milestones & Timeline (TBD)
1. **Week 1**: Finalize IOCs, design architecture, prototype filesystem walker.
2. **Week 2**: Implement parallel scanning, telemetry, basic CLI UX.
3. **Week 3**: Remote repo cloning, JSON reporting, packaging pipeline.
4. **Week 4**: Documentation, testing, release automation, pilot rollout.

## 10. Out of Scope & Future Enhancements
- Automatic removal/quarantine of infected files (consider optional flag later).
- Live signature updates from remote API.
- Real-time daemon monitoring newly installed packages.
- Integration with SIEM/SOAR platforms.

## 11. Open Questions
- Location/format of central IOC registry? JSON in repo vs remote fetch.
- How to handle private Git repo authentication securely (env vars vs keychain)?
- Do we bundle all binaries inside npm package or download on install (affects package size)?
- Should we integrate with OS notifications when detections found?

## 12. Appendix: Reference IOCs (Initial)
- Filenames: `shai-hulud.js`, `shai-hulud/index.js`, `sexo.js`, `th3Gr00t.js`, `postinstall.js` with HTTP fetches.
- Strings: `fetch("https://shai-hulud[.]xyz"`, `pkg.installScripts.postinstall`, `powershell.exe -` with base64 payload.
- Hashes (placeholder, replace with actual): `TODO: populate from threat intel`.
- Behavior: postinstall hooking, credential theft via environment scraping, exfil to remote server.

