# Issues — Hash.MassDownloader

Product issue register. IDs are stable (`HMD-NNN`). Newest first.

| ID | Title | Status | Notes |
|----|-------|--------|-------|
| HMD-016 | Rename product Vt/Vtm/VTM → Hash/Hmd/HMD | done | Module `Hash.MassDownloader`; keep VT provider tokens; folder `hash-mass-downloader` |
| HMD-014 | Persist VT Harmless to scanlog + hashcache CSV | done | Column after Undetected |
| HMD-013 | DisplaySummary/DisplayScanLog defaults + entry `-AgentSummary` | done | `HMD-RUN-OK` / `HMD-RUN-FAIL` |
| HMD-012 | Clarify CacheHit vs checkpoint resume in docs + summary flags | done | SkippedByCheckpoint / RecordsArePriorScanlog |
| HMD-011 | Document all log/report/VT fields (incl. Undetected) in product brief | done | Field reference + VT stats semantics |
| HMD-010 | Flatten download-pool results (ProcessedCount 1 / Path type error) | done | ConvertTo-HmdFlatArray + NoEnumerate download return |
| HMD-009 | Fix `@()` nest join of URL list (InputCount 1) | done | Assign Import-HmdUrlList directly; NoEnumerate [string[]] |
| HMD-008 | Harden URL list parse (multi-URL line) + downloadable sample | done | Live smoke showed concatenated `example.com` URLs → 404 |
| HMD-004 | Validate trio (Pester + PSA + Invoke-HmdValidate) | done | `scripts/Invoke-HmdValidate.ps1` |
| HMD-003 | MVP pipeline: download, VT hash lookup, cache, quarantine, report, resume | done | Module `Invoke-HmdBulkDownload`; upload opt-in |
| HMD-002 | Module scaffold + defaults config + entry script | done | `src/Hash.MassDownloader/`, `config/hmd.defaults.json` |
| HMD-001 | Product brief from draft specs | done | `docs/product-brief.md` |

## Backlog (post-v0.1)

| ID | Title | Status | Notes |
|----|-------|--------|-------|
| HMD-015 | Extend `hashcache.Source` beyond VirusTotal | backlog | Controlled vocabulary + optional providers; see candidates in issue notes |
| HMD-005 | SQLite hash cache | backlog | Roadmap |
| HMD-006 | Archive inspection (HPI/JPI/JAR) | backlog | Roadmap |
| HMD-007 | SIEM / scheduler / enterprise reporting | backlog | Roadmap |

### HMD-015 notes — candidate `Source` values

Today every live cache write uses `VirusTotal`. Useful extensions:

| Candidate | When it would apply |
|-----------|---------------------|
| `VirusTotal` | Hash report or upload analysis (current) |
| `VirusTotalUpload` | Optional finer split: sample was submitted, not hash-only |
| `SkipVirusTotal` / `LocalOnly` | `-SkipVirusTotal` path if those runs ever write cache |
| `Manual` / `OperatorOverride` | Operator-seeded or edited cache row |
| `Import` / `Seed` | Bulk import / migration into hashcache |
| `HybridAnalysis` | Hybrid Analysis hash/report API |
| `MalwareBazaar` | abuse.ch MalwareBazaar (known-sample intel) |
| `MetaDefender` | OPSWAT MetaDefender Cloud |
| `ReversingLabs` | RL Titanium / Spectra |
| `Microsoft` | Defender / cloud hash reputation (enterprise) |
| `OTX` | AlienVault OTX pulse/hash |
| `LocalScanner` | Local AV/YARA/AMSI-derived disposition |

Keep `Source` a short stable token (not free text). Multi-provider merges need a rule (prefer highest severity, or keep first writer + separate columns).

