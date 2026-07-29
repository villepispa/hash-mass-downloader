# Changelog

All notable changes to **Hash.MassDownloader** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning aligns with [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing queued — latest release: **0.1.0**._

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
