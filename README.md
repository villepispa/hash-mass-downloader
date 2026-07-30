# Hash.MassDownloader

PowerShell 7.2+ bulk URL downloader with SHA256-first hash reputation
(**VirusTotal** is the first provider), local hash cache, **Microsoft Defender
hard-gate scan**, quarantine disposition, CSV audit logs, HTML reporting, resume
checkpoints, optional leaf-name prefix, and post-Clean deploy maps (TXT/CSV with
`-like` wildcards and optional `http(s)` File entries).

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
`PrefixFileNames` defaults to `true`; set false in config or pass
`-NoFileNamePrefix`. `LocalAvScanEnabled` defaults to `true`.

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

## Release

Bump version strings **before** the release commit (see [docs/release.md](docs/release.md)):

```powershell
pwsh -NoProfile -File .\scripts\Invoke-HmdBumpVersion.ps1 -Version 0.2.1 -WhatIf
pwsh -NoProfile -File .\scripts\Invoke-HmdBumpVersion.ps1 -Version 0.2.1 `
  -ReleaseNotes 'v0.2.1 — …'
```

## AI assistance

See [docs/ai-assistance-log.md](docs/ai-assistance-log.md).
