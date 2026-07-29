# Hash.MassDownloader

PowerShell 7.2+ bulk URL downloader with SHA256-first hash reputation
(**VirusTotal** is the first provider), local hash cache, quarantine disposition,
CSV audit logs, HTML reporting, and resume checkpoints.

**License:** [MIT](LICENSE) · **Spec:** [docs/product-brief.md](docs/product-brief.md)

## Quick start

```powershell
# API key (never commit)
$env:VIRUSTOTAL_API_KEY = '<your-key>'

pwsh -NoProfile -File .\scripts\Invoke-HmdBulkDownload.ps1 `
  -InputPath .\examples\urls.sample.txt `
  -WorkRoot .\out\run1
```

Download-only (no VT):

```powershell
pwsh -NoProfile -File .\scripts\Invoke-HmdBulkDownload.ps1 `
  -InputPath .\examples\urls.sample.txt `
  -WorkRoot .\out\run1 `
  -SkipVirusTotal
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
# → HMD-RUN-OK input=… pending=… processed=… …
```

Post-run host display is controlled by `config/hmd.defaults.json`
(`DisplaySummary`, `DisplayScanLog`; both default `true`).

## Layout

| Path | Role |
|------|------|
| `docs/product-brief.md` | Full technical specification + **field reference** (incl. VT Undetected) |
| `docs/issues.md` | Product issue register (`HMD-*`) |
| `config/hmd.defaults.json` | Delays, threads, TTL, quarantine policy |
| `src/Hash.MassDownloader/` | Module (Public + Private) |
| `scripts/Invoke-HmdBulkDownload.ps1` | Operator entry |
| `scripts/Invoke-HmdValidate.ps1` | Pester + PSA gate |
| `examples/urls.sample.txt` | Sample TXT input |

## Work root folders

`Downloaded`, `Clean`, `Suspicious`, `Malicious`, `Quarantine`, `Unknown`,
`Error`, `logs/`, `reports/`.

## Validate

```powershell
Install-Module -Name Pester -MinimumVersion 5.5.0 -Scope CurrentUser -Force -SkipPublisherCheck
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -SkipPublisherCheck

pwsh -NoProfile -File .\scripts\Invoke-HmdValidate.ps1 -AgentSummary
```

## AI assistance

See [docs/ai-assistance-log.md](docs/ai-assistance-log.md).
