# Hash.MassDownloader

PowerShell 7.2+ bulk URL downloader with SHA256-first hash reputation
(**VirusTotal** is the first provider), local hash cache, **Microsoft Defender
hard-gate scan**, quarantine disposition, CSV audit logs, HTML reporting, resume
checkpoints, optional leaf-name prefix, post-Clean deploy maps (TXT/CSV with
`-like` wildcards and optional `http(s)` File entries), **opt-in ZIP-family
archive inspection** with selective member VT (`ArchiveVtMode`), a **Phase 1
inbox worker** (Scheduled Task / CredMan API key / single-instance mutex),
**live progress** (host + `progress.log`), and a **split archive-member scan
log** (`archive-scanlog.csv`).

**License:** [MIT](LICENSE) · **Spec:** [docs/product-brief.md](docs/product-brief.md) · **Release:** [docs/release.md](docs/release.md)

## Quick start

```powershell
# API key (never commit)
$env:VIRUSTOTAL_API_KEY = '<your-key>'

pwsh -NoProfile -File .\scripts\Invoke-HmdBulkDownload.ps1 `
  -InputPath .\examples\urls.sample.txt `
  -WorkRoot .\out\run1
```

Download-only (no VT; still runs local Defender unless skipped):

```powershell
pwsh -NoProfile -File .\scripts\Invoke-HmdBulkDownload.ps1 `
  -InputPath .\examples\urls.sample.txt `
  -WorkRoot .\out\run1 `
  -SkipVirusTotal
```

Deploy-map only (URLs in the map are downloaded + matched):

```powershell
pwsh -NoProfile -File .\scripts\Invoke-HmdBulkDownload.ps1 `
  -DeployMapPath .\examples\deploy.sample.txt `
  -WorkRoot .\out\run1
```

Skip local Defender (labs / hosts without MpCmdRun):

```powershell
pwsh -NoProfile -File .\scripts\Invoke-HmdBulkDownload.ps1 `
  -InputPath .\examples\urls.sample.txt -WorkRoot .\out\run1 `
  -SkipLocalAvScan
```

Upload unknown samples (opt-in):

```powershell
pwsh -NoProfile -File .\scripts\Invoke-HmdBulkDownload.ps1 `
  -InputPath .\urls.txt -WorkRoot .\out\run2 -UploadUnknownSamples
```

Agent one-liner (suppresses host summary/scanlog table):

```powershell
pwsh -NoProfile -File .\scripts\Invoke-HmdBulkDownload.ps1 `
  -InputPath .\examples\urls.sample.txt -WorkRoot .\out\run1 -AgentSummary
# → HMD-RUN-OK input=… queued=… processed=… … deploy=…
```

Optional leaf names (no `NNNN_` prefix) + copy Clean files after triage
(wildcards like `*.pgi` and `http(s)` URLs allowed in the deploy map):

```powershell
pwsh -NoProfile -File .\scripts\Invoke-HmdBulkDownload.ps1 `
  -InputPath .\examples\urls.sample.txt -WorkRoot .\out\run1 `
  -NoFileNamePrefix -DeployMapPath .\examples\deploy.sample.txt
```

Post-run host display is controlled by `config/hmd.defaults.json`
(`DisplaySummary`, `DisplayScanLog`; both default `true`).
`DisplayArchiveScanLog` dumps `logs/archive-scanlog.csv` (archive members);
it defaults **false** so `ArchiveVtMode` Interesting/All does not flood the
terminal. Live progress during the run uses `DisplayProgress` (bar + host
lines) and `ProgressLog` (`logs/progress.log`); both default `true`.
`-AgentSummary` quiets summary, scanlog table, archive-scanlog table, and
host progress (the file logs still write). `PrefixFileNames` defaults to
`true`; set false in config or pass `-NoFileNamePrefix`. `LocalAvScanEnabled`
defaults to `true`.
Archive inspection is **off** by default (`ArchiveInspectionEnabled`); when
enabled, member VT defaults to **None** (`ArchiveVtMode` / hash-only). Set
`ArchiveVtMode` to `Interesting` to VT high-risk members only, or `All` for
every member. Member rows always go to `logs/archive-scanlog.csv` (not the
host `scanlog.csv` table).

## Inbox worker (Phase 1)

Drop URL lists into `incoming/`. Optionally place a **deploy sidecar** beside
each list so the worker passes `-DeployMapPath` automatically:

| Input (claimed) | Optional sidecar |
|-----------------|------------------|
| `urls.txt` / `urls.csv` | `urls.deploy.txt` or `urls.deploy.csv` |
| `batch01.txt` | `batch01.deploy.txt` / `batch01.deploy.csv` |

Same stem, same folder. If both `.deploy.txt` and `.deploy.csv` exist,
`.deploy.txt` wins. Orphan sidecars (no matching input) stay unclaimed.
Sample pair: [`examples/inbox/`](examples/inbox/).

A Scheduled Task (or manual run) processes **one job at a time**:

```powershell
# Store VT key for the task user (once)
pwsh -NoProfile -File .\scripts\Register-HmdApiKeyCredential.ps1

# Register 5-minute poll (current user)
pwsh -NoProfile -File .\scripts\Register-HmdInboxScheduledTask.ps1 `
  -InboxRoot 'D:\Hmd\inbox' -WorkRootBase 'D:\Hmd\jobs' -Force

# Copy examples into the inbox, then run once
Copy-Item .\examples\inbox\urls.txt, .\examples\inbox\urls.deploy.txt `
  'D:\Hmd\inbox\incoming\'
pwsh -NoProfile -File .\scripts\Invoke-HmdInboxWorker.ps1 `
  -InboxRoot 'D:\Hmd\inbox' -WorkRootBase 'D:\Hmd\jobs' `
  -SkipVirusTotal -AgentSummary
```

Layout under the inbox root: `incoming/` → `processing/` → `done/` or
`failed/` (failures get `*.err.txt`; input + sidecar move together).
Overlapping workers fail closed on the named mutex
(`Local\Hash.MassDownloader.Inbox` by default).

## Layout

| Path | Role |
|------|------|
| `docs/product-brief.md` | Full technical specification + **field reference** (incl. VT Undetected); **operator pitfalls** (URL vs file VT reports; single-engine Malicious) |
| `docs/release.md` | SemVer bump + tag/release checklist |
| `docs/issues.md` | Product issue register (`HMD-*`) |
| `config/hmd.defaults.json` | Delays, threads, TTL, quarantine policy |
| `src/Hash.MassDownloader/` | Module (Public + Private) |
| `scripts/Invoke-HmdBulkDownload.ps1` | Operator entry |
| `scripts/Invoke-HmdBumpVersion.ps1` | Align ModuleVersion / UserAgent / Status |
| `scripts/Invoke-HmdValidate.ps1` | Version sync + Pester + PSA gate |
| `examples/urls.sample.txt` | Sample TXT input |
| `examples/inbox/` | Sample inbox drop: `urls.txt` + `urls.deploy.txt` sidecar |
| `examples/deploy.sample.txt` | Sample Clean-deploy map (sectioned TXT) |
| `examples/deploy.sample.csv` | Sample Clean-deploy map (CSV) |

## Work root folders

`Downloaded`, `Clean`, `Suspicious`, `Malicious`, `Quarantine`, `Unknown`,
`Error`, `logs/`, `reports/`.

## Validate

```powershell
Install-Module -Name Pester -MinimumVersion 5.5.0 -Scope CurrentUser -Force -SkipPublisherCheck
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -SkipPublisherCheck

pwsh -NoProfile -File .\scripts\Invoke-HmdValidate.ps1 -AgentSummary
```

Optional Task palette (needs `CURSOR_CONFIG_ROOT`): `.vscode/tasks.json`.

## Release

Bump version strings **before** the release commit (see [docs/release.md](docs/release.md)):

```powershell
pwsh -NoProfile -File .\scripts\Invoke-HmdBumpVersion.ps1 -Version 0.2.1 -WhatIf
pwsh -NoProfile -File .\scripts\Invoke-HmdBumpVersion.ps1 -Version 0.2.1 `
  -ReleaseNotes 'v0.2.1 — …'
```

## AI assistance

See [docs/ai-assistance-log.md](docs/ai-assistance-log.md).
