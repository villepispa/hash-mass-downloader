# Changelog

All notable changes to **Hash.MassDownloader** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning aligns with [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **HMD-048**: GitHub Actions `virustotal-release-scan` on `release: published`
  (repo secret `VIRUSTOTAL_API_KEY`; never committed).

## [0.6.0] - 2026-08-21

### Added

- **HMD-047**: archive members write `logs/archive-scanlog.csv`;
  `DisplayArchiveScanLog` (default false) dumps that table. `DisplayScanLog`
  stays top-level so Interesting/All does not flood the host.

- Repo-root markdownlint (`.markdownlint.json` + `.markdownlint-cli2.jsonc`
  ignores for `.cursor/` and drafts).
- Call-through VS Code tasks (`.vscode/tasks.json`); default ScriptSafetyGate
  path is `scripts/Invoke-HmdValidate.ps1`.

- **HMD-046**: live progress for download / process / deploy — `Write-Progress`
  plus host START/ITEM/DONE lines (`DisplayProgress`) and append-only
  `logs/progress.log` (`ProgressLog`); both default true. `-AgentSummary`
  quiets host/bar; the file log still writes unless `ProgressLog` is false.

### Changed

- ModuleVersion / UserAgent / Status → **0.6.0**.
- Product brief Scope → v0.6.0 (live progress + split archive-scanlog).

## [0.5.0] - 2026-07-31

### Added

- **HMD-028**: Serial inbox worker (`Invoke-HmdInboxWorker` /
  `scripts/Invoke-HmdInboxWorker.ps1`); optional deploy sidecar
  `stem.deploy.txt|csv`; `Register-HmdInboxScheduledTask.ps1` poll task.
- **HMD-034**: VT API key via Windows Credential Manager (default target
  `Hash.MassDownloader/VirusTotal`); `Register-HmdApiKeyCredential.ps1`;
  resolve order `-ApiKey` → CredMan → `VIRUSTOTAL_API_KEY`.
- **HMD-035**: Named mutex (fail-closed) + inbox folders
  `incoming` / `processing` / `done` / `failed` (+ `.err.txt` on failure).

### Changed

- ModuleVersion / UserAgent / Status → **0.5.0**.
- Product brief Scope → v0.5.0 (Phase 1 inbox slice in-scope; GUI still roadmap).
- Inbox deploy sidecar: operator docs + `examples/inbox/` sample pair
  (`urls.txt` + `urls.deploy.txt`); Pester covers csv preference, orphans,
  and worker `-DeployMapPath` pass-through.

## [0.4.0] - 2026-07-31

### Added

- **HMD-045**: selective VT for interesting archive members —
  `ArchiveVtMode` (`None`/`All`/`Interesting`); interest heuristics
  (extension / path / MZ); `ArchiveInterestReason` scanlog column;
  back-compat via `ArchiveContentsHashOnly`.
- **HMD-006**: ZIP-family archive inspection (`.zip` / `.jar` / `.hpi` / `.jpi`);
  `ArchiveInspectionEnabled` (default false); `ArchiveContentsHashOnly` (default
  true); zip-slip-safe extract under `Inspected/`; `#archive/` scanlog rows;
  optional member VT + worst-of roll-up when hash-only is false.
- Roadmap backlog **HMD-028–HMD-044**: Phase 1 inbox watcher / Scheduled Task +
  PS GUI; Phase 2 web + AD/Entra SSO + per-group path ACL; Phase 3 other IdPs
  plus gap stories (secrets, mutex/inbox, job history, webhooks, egress,
  air-gap, HA, K8s, Malicious-override, SCIM, Intune dual-host).
  Issues + product-brief phased roadmap; OSS hub rows.
- Phase 1 first slice (**HMD-028/034/035**); GUI HMD-029 deferred.

### Changed

- ModuleVersion / UserAgent / Status → **0.4.0**.
- Product brief **Scope** → v0.4.0 in-scope (archive inspection + selective VT).

## [0.3.0] - 2026-07-30

### Added

- **HMD-026**: Local Microsoft Defender hard-gate scan after download
  (`LocalAvScanEnabled`, `LocalAvProvider`, `-SkipLocalAvScan`); threat →
  Malicious (skip VT); unavailable/error → Error; scanlog `DefenderStatus` /
  `DefenderThreat`; HTML Defender column.
- **HMD-027**: Deploy-map `http(s)` File entries harvested into the download
  queue and matched by full URL; `-InputPath` optional when the map has ≥1 URL.
- **HMD-025**: FP-aware VT verdict — config `IgnoreEngines` (default `[]`);
  `Get-HmdPolicyStatsFromResults` excludes named engines from policy counts;
  scanlog/hashcache keep **raw** VT tallies and record `IgnoredEngines`;
  verdict/quarantine/cache use policy counts.
- Product-brief operator pitfalls: VirusTotal **URL report ≠ file report**
  (HMD uses SHA-256 file API only); default `MaliciousThreshold=1` + ChromeDriver
  / VirIT `Win95.Marburg` worked example.
- Release pipeline: `docs/release.md`, `scripts/Invoke-HmdBumpVersion.ps1`
  (align ModuleVersion / UserAgent / Status); validate runs `-CheckOnly`
  (`HMD-024`).

### Changed

- ModuleVersion / UserAgent / Status → **0.3.0**.
- Product brief **Scope** → v0.3.0 in-scope (local AV + deploy-map URLs + HMD-025).

## [0.2.0] - 2026-07-30

### Added

- Document deploy-map wildcards as PowerShell **`-like`** (`*` / `?`, not regex)
  in issues, product brief, and sample map comments (`HMD-023`).
- Deploy-map wildcards (`*` / `?`): e.g. `program.exe` → app folder and
  `*.pgi` → plugins folder; expands to all Clean matches (`HMD-023`).
- Backlog: Clean-deploy dry-run (`HMD-020`), Sha256/Url match (`HMD-021`),
  explicit rename (`HMD-022`).
- Optional staged-name prefix: config `PrefixFileNames` (default true) and
  entry `-NoFileNamePrefix`; collision disambiguation without prefix (`HMD-018`).
- Post-Clean deploy: `-DeployMapPath` sectioned TXT (`@dest` blocks) or CSV
  (`Destination,File`); create missing folders; copy (keep `Clean/`);
  `logs/deploy_copy.csv`; `DeployOverwrite` (`HMD-019`).

### Changed

- Rename summary field `PendingCount` → `QueuedCount` (start-of-run queue;
  not leftover after a successful run); locals `$queued` / `$queuedList`;
  host line `Input / Queued`; agent token `queued=` (`HMD-017`).

## [0.1.0] - 2026-07-29

### Changed

- Product identity rename: `Vt.MassDownloader` / `Vtm` / `VTM-*` →
  `Hash.MassDownloader` / `Hmd` / `HMD-*`; entry `Invoke-HmdBulkDownload`;
  config `hmd.defaults.json`; agent lines `HMD-RUN-*` / `HMD-VALIDATE-*`.
  VirusTotal remains the v0.1 provider (`VIRUSTOTAL_API_KEY`, `-SkipVirusTotal`,
  `Source=VirusTotal`) (`HMD-016`).
- Product brief documents all scan/cache/download/checkpoint/console fields,
  including VT **Undetected** engine counts (`HMD-011`).
- Clarify checkpoint vs hash-cache; console adds `SkippedByCheckpoint` /
  `RecordsArePriorScanlog` so resume runs are not mistaken for cache misses
  (`HMD-012`).

### Fixed

- TXT/CSV import splits whitespace-separated URLs on one line; sample list uses
  downloadable fixtures instead of `example.com` 404 placeholders (`HMD-008`).
- `Invoke-HmdBulkDownload` no longer wraps `Import-HmdUrlList` in `@()`, which
  nested a `[string[]]` and joined URLs with a space (`InputCount: 1`) (`HMD-009`).
- Same nesting bug for `Start-HmdDownloadPool` results (member-enumeration /
  `Move-HmdByVerdict` Path type error); added `ConvertTo-HmdFlatArray` (`HMD-010`).

### Added

- Persist VT **Harmless** engine count to `scanlog.csv` and `hashcache.csv`;
  console summary adds `HarmlessSum` / `UndetectedSum` (`HMD-014`).
- `DisplaySummary` / `DisplayScanLog` defaults (host post-run summary + scanlog
  table); entry script `-AgentSummary` emits `HMD-RUN-OK` / `HMD-RUN-FAIL`
  (`HMD-013`).
- v0.1.0 MVP scaffold: product brief, PS 7.2 module, bulk download + SHA256-first
  VirusTotal lookup (upload opt-in), hash cache, checkpoint resume, quarantine
  folders, CSV logs, HTML report, Pester mocks, validate trio (`HMD-001`–`HMD-004`).
- Initial public tree under MIT license.
