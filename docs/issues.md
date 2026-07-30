# Issues — Hash.MassDownloader

Product issue register. IDs are stable (`HMD-NNN`). Newest first.

| ID | Title | Status | Notes |
|----|-------|--------|-------|
| HMD-017 | Rename summary PendingCount → QueuedCount | done | Locals `$queued`/`$queuedList`; agent `queued=`; host `Input / Queued` |
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
| HMD-023 | Deploy-map globs / wildcards (`*.pgi`) | done | `*` / `?` via `-like`; expands to all Clean matches; Miss if zero |
| HMD-022 | Deploy-map explicit rename (`tool.exe → app.exe`) | backlog | Dest leaf differs from source leaf |
| HMD-021 | Deploy-map match by Sha256 / Url columns | backlog | CSV (and optional TXT) keys beyond FileName |
| HMD-020 | Clean-deploy dry-run | backlog | Preview copies without writing; log Status=WouldCopy |
| HMD-019 | Copy Clean files to mapped destinations | done | Sectioned TXT + CSV map; create dirs; copy+audit CSV; unmatched warn |
| HMD-018 | Optional `NNNN_` download filename prefix | done | Config `PrefixFileNames` (default true); `-NoFileNamePrefix`; collision disambiguation |
| HMD-015 | Extend `hashcache.Source` beyond VirusTotal | backlog | Controlled vocabulary + optional providers; see candidates in issue notes |
| HMD-005 | SQLite hash cache | backlog | Roadmap |
| HMD-006 | Archive inspection (HPI/JPI/JAR) | backlog | Roadmap |
| HMD-007 | SIEM / scheduler / enterprise reporting | backlog | Roadmap |

### HMD-018 notes

Staged names under `Downloaded/` / verdict folders historically use `{index:D4}_{leaf}`
(`0000_tool.exe`). Operators who want the original leaf for deploy/tools can set
`PrefixFileNames: false` or pass `-NoFileNamePrefix`. When the prefix is off and
two URLs share a leaf, the second gets `name_<index>.ext` before write.

### HMD-019 notes

After Clean disposition, optionally copy (not move) into operator-defined folders.

**Primary map (TXT)** — destination blocks, `#` comments, blank lines ignored:

```text
@C:\Deploy\App1
program.exe

@C:\Deploy\App1\Plugins
*.pgi

@D:\Tools\Bin
tool.exe
```

**CSV** — columns `Destination` + `File` (aliases: `Path`/`Dest`, `FileName`/`Name`):

```csv
Destination,File
C:\Deploy\App1,program.exe
C:\Deploy\App1\Plugins,*.pgi
```

Match `File` against staged `FileName`, leaf without `NNNN_` prefix, or URL path leaf.
Create missing destination folders. Log `logs/deploy_copy.csv`. Config:
`DeployOverwrite` (default true). Entry: `-DeployMapPath`.

**Wildcard matching (`HMD-023`)** — when `File` contains `*` or `?`, matching uses
PowerShell’s **`-like`** operator (not regex, not `-match`):

| Pattern | Meaning (`-like`) |
|---------|-------------------|
| `*` | Any sequence of characters (including empty) |
| `?` | Exactly one character |
| (no `*` / `?`) | Exact match (case-insensitive) |

Examples: `*.pgi` → all Clean leaves ending in `.pgi`; `file?.dll` → `file1.dll`,
`fileA.dll`, not `file10.dll`. Matching is **case-insensitive**. A glob expands to
**all** matching Clean files (one audit row per copy). Character classes such as
`[a-z]` are **not** supported for map patterns (only `*` and `?` trigger glob mode).
Prefixed staged names still match via the stripped leaf (`0002_plug.pgi` ↔ `*.pgi`
→ dest leaf `plug.pgi`).

### HMD-020–022 notes (deferred from HMD-019 follow-ups)

| ID | Intent |
|----|--------|
| HMD-020 | `-DeployDryRun` / config: resolve map and write WouldCopy rows without `Copy-Item` |
| HMD-021 | Optional CSV columns `Sha256`, `Url` for disambiguation when leaves collide |
| HMD-022 | Rename on deploy: map `source → destLeaf` or CSV `DestFile` |

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

