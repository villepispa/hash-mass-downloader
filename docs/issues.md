# Issues — Hash.MassDownloader

Product issue register. IDs are stable (`HMD-NNN`). Newest first.

| ID | Title | Status | Notes |
|----|-------|--------|-------|
| HMD-027 | Deploy-map http(s) URLs: harvest + full-URL match | done | Optional InputPath when map has ≥1 URL |
| HMD-026 | Local AV scan (MS Defender); hard gate on threat | done | Start-MpScan / MpCmdRun; scanlog DefenderStatus |
| HMD-024 | Release pipeline: bump version before commit/tag | done | `Invoke-HmdBumpVersion.ps1`; validate `-CheckOnly`; `docs/release.md` |
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

## Backlog

| ID | Title | Status | Notes |
|----|-------|--------|-------|
| HMD-025 | FP-aware VT verdict policy (threshold + engine ignore) | done | ChromeDriver VirIT `Win95.Marburg`; see notes |
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

### HMD-026 notes — local AV hard gate (Microsoft Defender)

After successful download (SHA-256 + Authenticode), before VT/cache:

1. Config `LocalAvScanEnabled` (default `true`), `LocalAvProvider` (`Defender`).
2. `-SkipLocalAvScan` disables the gate for labs / hosts without Defender.
3. `Invoke-HmdLocalAvScan`: `Start-MpScan` CustomScan, else `MpCmdRun.exe -ScanType 3`.
4. **Threat** → `Verdict=Malicious`, quarantine per policy, skip VT, no Clean deploy.
5. **Unavailable** / **Error** → `Verdict=Error` (do not deploy unscanned).
6. scanlog: `DefenderStatus`, `DefenderThreat`. MOTW alone is not sufficient.

### HMD-027 notes — deploy-map http(s) URLs

Map `File` may be an `http://` / `https://` URL:

1. Harvested into the download queue (merged with `-InputPath`, unique).
2. Matched for Clean deploy by **full URL** (plus existing leaf keys).
3. Dest leaf = URL path leaf (never the URL string).
4. `-InputPath` optional when the map yields ≥1 harvested URL.

### HMD-020–022 notes (deferred from HMD-019 follow-ups)

| ID | Intent |
|----|--------|
| HMD-020 | `-DeployDryRun` / config: resolve map and write WouldCopy rows without `Copy-Item` |
| HMD-021 | Optional CSV columns `Sha256`, `Url` for disambiguation when leaves collide (full URL as File is HMD-027) |
| HMD-022 | Rename on deploy: map `source → destLeaf` or CSV `DestFile` |

### HMD-025 notes — false-positive–aware verdict policy

**Trigger (2026-07-30):** Official Chrome for Testing
`chromedriver-win64.zip` (SHA-256 `87368d15…`) dispositioned **Malicious** with
`Malicious=1`, `Suspicious=0`, `Undetected=65`. Live VT API named engine
**VirIT** / result `Win95.Marburg` — a known noisy FP. Default
`MaliciousThreshold: 1` is correct per current policy but over-quarantines
trusted bulk downloads.

**Acceptance:**

1. Config knobs (defaults stay conservative / documented):
   - Keep `MaliciousThreshold` / `SuspiciousThreshold` (operators may raise to 2–3).
   - Optional `IgnoreEngines` (string array of VT engine names, case-insensitive)
     excluded from the counts that feed `Get-HmdVerdictFromStats`.
2. When engines are ignored, still persist **raw** VT stats on the scanlog row
   (today’s `Malicious`/`Suspicious`/…) **and** `IgnoredEngines` for audit clarity.
3. Cache writes use the **policy verdict** (post-ignore), and record
   `IgnoredEngines` so operators see what was applied; TTL refresh re-applies the
   **current** ignore list after a fresh VT fetch.
4. Docs: product-brief verdict section + defaults comments; Pester cases for
   threshold-only, ignore-only, and both.
5. Out of scope for this story: automatic community-score heuristics; per-URL
   allowlists (file separately if needed).

**Docs (done ahead of code):** product-brief § *Operator pitfall — URL report ≠
file report* and § *Operator pitfall — one noisy engine → Malicious* (ChromeDriver
/ VirIT worked example). README points operators at those sections.

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

