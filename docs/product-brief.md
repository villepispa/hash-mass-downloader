# Hash-Assisted Bulk File Downloader

Comprehensive technical specification and design document for **Hash.MassDownloader**
(`Hmd` prefix, issue IDs `HMD-*`).

**Host floor:** PowerShell 7.2+  
**License:** MIT  
**Status:** v0.6.0 — core pipeline, Clean deploy, Defender hard gate, archive inspection, Phase 1 inbox, live progress, split archive-scanlog; remaining roadmap items below are documented only.

---

## Executive summary

PowerShell-based bulk downloader with SHA256-first hash reputation triage
(VirusTotal is the current provider; naming is scanner-agnostic for HMD-015),
optional file submission, quarantine handling, reporting, audit logging, and
resume capabilities.

## Business objectives

- Reduce manual malware triage
- Automate reputation checks
- Provide auditable results
- Minimize VirusTotal API consumption through SHA256-first lookups and local caching

## Scope

### In scope (v0.6.0)

| Capability | Notes |
|------------|-------|
| TXT and CSV URL input | Whitespace-split multi-URL lines |
| Parallel downloads (5–10) | Config `DownloadThreads` |
| SHA256 calculation | Per successful download |
| VirusTotal API v3 | Hash lookup; upload opt-in |
| Authenticode advisory validation | Non-blocking |
| Local AV hard gate (Defender) | HMD-026; threat → Malicious; unavailable → Error |
| Quarantine workflows | Config thresholds |
| Logging, HTML reporting, resume | CSV + checkpoint |
| Optional `NNNN_` filename prefix | HMD-018; `-NoFileNamePrefix` |
| Clean deploy maps | TXT/CSV; `-like` wildcards (HMD-019/023) |
| Deploy-map http(s) URLs | Harvest + full-URL match; optional InputPath (HMD-027) |
| FP-aware VT verdict | Threshold + `IgnoreEngines`; raw counts + `IgnoredEngines` (HMD-025) |
| Archive inspection (ZIP/JAR/HPI/JPI) | HMD-006; opt-in; member hash-only by default |
| Selective archive-member VT | HMD-045; `ArchiveVtMode=Interesting` |
| Inbox serial worker + Scheduled Task | HMD-028; `incoming`→`processing`→`done`/`failed` |
| CredMan / env / `-ApiKey` for VT key | HMD-034; default target `Hash.MassDownloader/VirusTotal` |
| Single-instance inbox mutex | HMD-035; fail-closed when busy |
| Live progress (host + `progress.log`) | HMD-046; `DisplayProgress` / `ProgressLog` |
| Split archive-member scan log | HMD-047; `archive-scanlog.csv` + `DisplayArchiveScanLog` |
| Public GitHub repo + SemVer releases | Tags / GitHub Releases |

### Out of scope (roadmap)

| Capability | Tracking |
|------------|----------|
| SQLite hash cache | HMD-005 |
| SIEM / enterprise reporting | HMD-007 |
| PowerShell GUI for input | HMD-029 (Phase 1) |
| Web front-end + modern back-end | HMD-030 (Phase 2) |
| AD / Entra ID SSO access control | HMD-031 (Phase 2) |
| Download/output folder ACL per AD group | HMD-032 (Phase 2) |
| Other popular IdPs (Okta / Keycloak / …) | HMD-033 (Phase 3) |
| Job history / retention / evidence export | HMD-036 |
| Notifications / webhooks | HMD-037 |
| Network egress allowlist / proxy | HMD-038 |
| Air-gapped / offline reputation mode | HMD-039 |
| HA multi-node workers | HMD-040 |
| Container / Kubernetes packaging | HMD-041 |
| Malicious-override approval workflow | HMD-042 |
| SCIM provisioning | HMD-043 |
| Intune / PS 5.1 dual-host | HMD-044 |
| Additional reputation providers | HMD-015 |
| Clean-deploy dry-run | HMD-020 |
| Deploy match by Sha256 column | HMD-021 (full URL as File: HMD-027) |
| Deploy-map explicit rename | HMD-022 |

## Architecture overview

A **download layer** performs parallel downloads while a **processing layer**
performs serialized VirusTotal operations to respect API quotas. Cache,
checkpoint, and reporting services persist state.

```text
Input (TXT/CSV) + deploy-map http(s) harvest
    → Download pool (concurrent)
    → Downloaded/
    → SHA256 + Authenticode
    → Local AV (Defender) ──Threat──→ Malicious / Quarantine
              │ Clean
              ↓
         Hash cache (TTL) ──hit──→ Classify
              │ miss
              ↓
         VT API (serialized)
              ↓
    optional archive inspect (HMD-006/045) → Inspected/ + #archive/ (+ selective VT)
              ↓
    Clean / Suspicious / Malicious / Quarantine / Unknown / Error
              ↓
    optional Clean deploy map
              ↓
    logs/*.csv + reports/report.html + checkpoint.json
```

## Functional requirements

1. **Input handling** — TXT (one URL per line; whitespace-separated URLs on a
   single line are split) and CSV (column `Url` or first column). Optional when
   `-DeployMapPath` contains ≥1 `http(s)` File entry (HMD-027).
2. **Retry logic** — transient HTTP failures; explicit handling for 404, 403, 429
3. **Content-type validation** — soft check (warn / record; do not hard-fail by default)
4. **Size limits** — skip or error when `Content-Length` or downloaded bytes exceed config
5. **Hash calculation** — SHA256 of each successfully downloaded file
6. **Duplicate detection** — same URL or same SHA256 within a run / cache
7. **Local AV hard gate** — Microsoft Defender custom scan after download (HMD-026);
   threat → Malicious (skip VT); scanner unavailable/error → Error; `-SkipLocalAvScan`
   to opt out. MOTW alone is not relied on.
8. **VT lookup** — SHA256-first `GET /api/v3/files/{hash}`
9. **VT upload fallback** — when hash unknown and `-UploadUnknownSamples` enabled
10. **Verdict classification** — from `last_analysis_stats` + policy thresholds
11. **HTML reporting** — KPIs, detection summaries, file inventory
12. **Resume support** — checkpoint after each processed URL; skip completed on restart
13. **Optional filename prefix** — `NNNN_` index prefix on staged names (`PrefixFileNames`;
    `-NoFileNamePrefix` to use the URL leaf)
14. **Clean deploy** — optional map-driven copy of Clean files to destinations
    (`-DeployMapPath`; create folders; keep `Clean/` as audit copy; `*` / `?`
    wildcards expand to all matches; `http(s)` File entries harvest + full-URL match)
15. **Archive inspection** — optional ZIP-family (`.zip` / `.jar` / `.hpi` / `.jpi`)
    member extract under `Inspected/` with zip-slip protection (HMD-006);
    `ArchiveInspectionEnabled` (default false); `ArchiveVtMode` `None` \| `All` \|
    `Interesting` (default `None`; `ArchiveContentsHashOnly` true/false maps to
    None/All when mode unset); `Interesting` VTs high-risk members only (HMD-045)
    and rolls up worst-of when any member VT runs
16. **Selective member VT** — extension / path-keyword / optional MZ heuristics;
    `ArchiveInterestReason` on `#archive/` rows in `archive-scanlog.csv` (HMD-045/047)
17. **Live progress** — `Write-Progress` plus host lines during download / process /
    deploy, and append-only `logs/progress.log` (HMD-046); `-AgentSummary` quiets
    host/bar unless `DisplayProgress` is overridden
18. **Archive-member log** — member rows write `logs/archive-scanlog.csv`; host
    dump is `DisplayArchiveScanLog` (default false) so `DisplayScanLog` stays
    top-level (HMD-047)

## Non-functional requirements

| NFR | Expectation |
|-----|-------------|
| Reliability | Isolate per-URL failures; continue batch |
| Maintainability | Module + Safety-tier entry scripts; Pester + PSA |
| Auditability | CSV scan log, archive-scanlog, hash cache, download index |
| API efficiency | Cache + serialized VT + configurable delay |
| Scalability | Configurable download thread count |
| Recoverability | Checkpoint + resume |
| Security | Quarantine policy; API key from env / SecureString; never log secrets |

## VirusTotal integration design

1. Look up by SHA256 first (`GET /api/v3/files/{hash}`).
2. When the hash is unknown and upload is enabled by policy:
   - `POST /api/v3/files` with the sample
   - Poll `GET /api/v3/analyses/{id}` until complete or timeout
3. Read VirusTotal `last_analysis_stats` (and analysis `stats` after upload).
4. Classify from those counts (see below).

API key: `$env:VIRUSTOTAL_API_KEY` or `-ApiKey` (SecureString). Never commit.

### VirusTotal `last_analysis_stats` fields

These are **engine counts** from VT’s multi-engine scan of a known hash — not
percentages and not “confidence scores.”

| VT / tool field | Meaning |
|-----------------|---------|
| **Malicious** | Number of engines that classified the sample as malicious |
| **Suspicious** | Number of engines that classified it as suspicious |
| **Undetected** | Number of engines that completed a scan and reported **no** detection |
| **Harmless** | Number of engines that explicitly marked it harmless (written to `scanlog.csv` / `hashcache.csv`) |

**Example:** `Malicious: 0`, `Suspicious: 0`, `Undetected: 60` means about sixty
engines scanned the file and none flagged it — a typical **Clean** profile for a
well-known benign hash (for example a popular favicon).

When the hash is **not found** on VT (and upload is off), there are no stats:
`Malicious` / `Suspicious` / `Undetected` / `Harmless` are recorded as `0` and the
verdict is **Unknown** (not “zero engines scanned”).

### Verdict classification

Policy counts feed the table below. With an empty `IgnoreEngines` list (default),
policy counts equal VirusTotal’s `last_analysis_stats`. When engines are ignored,
**scanlog / hashcache still store raw VT counts** in `Malicious` / `Suspicious` /
`Undetected` / `Harmless`; the **Verdict** (and quarantine) uses policy counts.
Applied ignores are recorded in `IgnoredEngines` (semicolon-separated).

| Verdict | Rule |
|---------|-------------|
| **Malicious** | Policy `Malicious >= MaliciousThreshold` (default 1) |
| **Suspicious** | Else policy `Suspicious >= SuspiciousThreshold` (default 1) |
| **Clean** | Else hash **known** on VT with zero policy malicious and zero policy suspicious (Undetected / Harmless may be &gt; 0) |
| **Unknown** | Hash not found and upload disabled or upload/analysis failed |
| **Error** | Download or processing failure (see `Error` field) |

**Config knobs**

| Key | Default | Role |
|-----|---------|------|
| `MaliciousThreshold` | `1` | Minimum policy malicious engines for **Malicious** |
| `SuspiciousThreshold` | `1` | Minimum policy suspicious engines for **Suspicious** |
| `IgnoreEngines` | `[]` | Case-insensitive VT engine names excluded from policy counts (needs `last_analysis_results` / analysis `results`; otherwise raw stats are used unchanged) |

**Undetected does not drive the verdict** by itself. A high Undetected count with
zero Malicious/Suspicious supports **Clean**; Undetected `0` with verdict
**Unknown** usually means “no VT report,” not “all engines clean.”

### Operator pitfall — URL report ≠ file report

HMD never asks VirusTotal “is this URL bad?” It downloads the bytes, hashes them,
and calls **`GET /api/v3/files/{sha256}`**. Disposition comes only from that
**file** report’s `last_analysis_stats` (and optional per-engine
`last_analysis_results` when `IgnoreEngines` is set).

Operators (and auditors) often paste the download URL into VirusTotal’s
search box. VT then opens a **URL** report (`/gui/url/…`), which uses a different
engine set (web reputation / Safe Browsing / phishing feeds — often shown as
**0 / 92** Clean). That page does **not** drive HMD, and file-only AV names such
as **VirIT** typically do not appear there.

| | URL report (browser paste) | File report (what HMD uses) |
|--|----------------------------|-----------------------------|
| VT UI path | `/gui/url/<id>/…` | `/gui/file/<sha256>/…` |
| API | `GET /api/v3/urls/…` (not used by HMD) | `GET /api/v3/files/{sha256}` |
| Engines | URL / site reputation (~90+) | File AV engines (~60–70 with a verdict) |
| `scanlog` link | Do **not** use the input URL alone | Use column **`Sha256`** |

**How to verify HMD’s verdict against the UI**

1. Open `logs/scanlog.csv` for the row.
2. Copy the **`Sha256`** value (lowercase hex).
3. Open `https://www.virustotal.com/gui/file/<Sha256>/detection`.
4. Compare the UI “N / M security vendors flagged…” line to
   raw `Malicious` / `Suspicious` / `Undetected` on the CSV row. The HMD
   **Verdict** may differ when `MaliciousThreshold` / `SuspiciousThreshold` /
   `IgnoreEngines` change policy counts.

### Operator pitfall — one noisy engine → Malicious

Default **`MaliciousThreshold` is `1`**: any single file engine with category
`malicious` yields verdict **Malicious** and (by default) a Quarantine copy.
That is intentional for high-sensitivity triage; it also means well-known
false positives quarantine legitimate packages.

**Worked example (2026-07-30)** — Chrome for Testing
`chromedriver-win64.zip` from
`https://storage.googleapis.com/chrome-for-testing-public/151.0.7922.71/win64/chromedriver-win64.zip`:

| Check | Result |
|-------|--------|
| Downloaded SHA-256 | `87368d15c1dffa5826f6d002a4440a20c9858bab09345a33d883912c2902b230` |
| HMD `scanlog` (defaults) | `Verdict=Malicious`, raw `Malicious=1`, `Suspicious=0`, `Undetected=65` |
| File UI | **1 / 66** — VirIT → `Win95.Marburg` (popular threat label `marburg/win95`) |
| URL UI for the same link | **0 / 92** Clean — unrelated to HMD’s decision |
| With `IgnoreEngines: ["VirIT"]` | raw counts unchanged; policy Malicious=0 → **Clean**; `IgnoredEngines=VirIT` |

Operators may also raise `MaliciousThreshold` (for example `2` or `3`) in
`config/hmd.defaults.json` or a config override. Both knobs can be combined.

## Download pipeline

- Download 5–10 files concurrently (default from config)
- Maintain `download_index.csv`
- Apply retries with backoff
- Enqueue successful downloads for serialized processing

## Cache design

CSV cache stores SHA256, verdict, detection counts, and cache date.
Entries refresh after a configurable TTL (default 7 days).

## Resume and recovery

Checkpoint after every processed file (JSON of completed URL keys).
Previously processed URLs are skipped on restart when the same `-WorkRoot` is used.

**Checkpoint vs hash cache (different layers):**

| Layer | File | What it skips / reuses |
|-------|------|------------------------|
| **URL resume** | `checkpoint.json` | Entire URL — no re-download, no re-hash, no VT call |
| **Hash cache** | `hashcache.csv` | VT verdict for a SHA-256 when a URL **is** processed again |

A second run on the same `-WorkRoot` with the same input typically shows
`QueuedCount: 0`, `ProcessedCount: 0`, and `SkippedByCheckpoint: N`. Console
`Records` are then **prior** `scanlog.csv` rows (`RecordsArePriorScanlog: true`),
including whatever `CacheHit` was on the **original** processing pass (usually
`False` because the first pass called VT and **wrote** the cache).

To observe `CacheHit: True`, the file must be **processed again** while a fresh
cache entry exists — for example delete `checkpoint.json` (keep `hashcache.csv`)
and re-run, or process a different URL that yields the same SHA-256.

## Logging and auditing

| Artefact | Role |
|----------|------|
| `logs/scanlog.csv` | Per-file processing record (top-level downloads; primary audit trail) |
| `logs/archive-scanlog.csv` | Archive-member rows (`#archive/<entry>`) when inspection ran (HMD-047) |
| `logs/hashcache.csv` | Persistent hash → verdict cache |
| `logs/download_index.csv` | Download attempt outcomes |
| `logs/progress.log` | Live phase/step lines (HMD-046; ISO timestamp, PHASE/STATUS) |
| `checkpoint.json` | Resume set (completed URLs) |
| Console JSON | Summary object from `Invoke-HmdBulkDownload` / entry script |
| `reports/report.html` | Human-readable KPIs + inventory |

### Field reference — `logs/scanlog.csv` (and console `Records[]`)

Top-level download rows. Archive members use the same columns in
`logs/archive-scanlog.csv` (HMD-047). Console `Records[]` still includes both.

| Field | Type | Meaning |
|-------|------|---------|
| `Url` | string | Source URL processed |
| `FileName` | string | Staged name: `NNNN_` + leaf when `PrefixFileNames` is true (default); else sanitized URL leaf (collision → `name_Index.ext`). Archive members (HMD-006): `#archive/<entry>` in `archive-scanlog.csv` — excluded from Clean deploy, summary KPIs, and `DisplayScanLog` |
| `LocalPath` | string | Final path after disposition (Clean / … / Error), or empty on early failure |
| `Sha256` | string | Lowercase hex SHA-256 of the downloaded bytes; empty if download failed |
| `Verdict` | string | `Clean` \| `Suspicious` \| `Malicious` \| `Unknown` \| `Error` |
| `Malicious` | int | **Raw** VT engines marking malicious (`0` if no VT report). Unchanged when engines are ignored — compare to VT UI. |
| `Suspicious` | int | **Raw** VT engines marking suspicious (`0` if no VT report) |
| `Undetected` | int | **Raw** VT engines that scanned with **no** detection (`0` if no VT report) |
| `Harmless` | int | **Raw** VT engines that explicitly marked harmless (`0` if no VT report; older CSV rows without the column normalize to `0` on load) |
| `IgnoredEngines` | string | Engines excluded from the **policy** counts that produced `Verdict` (semicolon-separated; empty when none applied). Older rows without the column normalize to empty. |
| `ArchiveInterestReason` | string | Why an `#archive/` member was selected for VT under `ArchiveVtMode=Interesting` (e.g. `ext:.exe;path:bin/`; empty when not interesting / not archive) (HMD-045) |
| `SignatureStatus` | string | `Get-AuthenticodeSignature` status (advisory). Often `UnknownError` / not applicable for non-PE assets (`.ico`, raw `.bin`) |
| `Signer` | string | Signer certificate subject when present; else empty |
| `DefenderStatus` | string | Local AV result: `Clean` \| `Threat` \| `Unavailable` \| `Error` \| `Skipped` (empty on older rows) |
| `DefenderThreat` | string | Threat name when `DefenderStatus=Threat`; else empty |
| `ContentType` | string | HTTP Content-Type when observed (soft metadata) |
| `Bytes` | long | Downloaded size in bytes |
| `CacheHit` | bool | `True` only when **this processing pass** reused a fresh `hashcache.csv` entry instead of calling VT. `False` on first VT lookup/write. Unchanged historical rows in `scanlog.csv` keep their original value when a later run only resumes via checkpoint. |
| `Error` | string | Failure message; empty on success |
| `ProcessedAt` | string | Local timestamp (ISO 8601) when the row was finalized |

### Field reference — `logs/hashcache.csv`

| Field | Type | Meaning |
|-------|------|---------|
| `Sha256` | string | Cache key (lowercase hex) |
| `Verdict` | string | Cached **policy** disposition verdict (post-threshold / IgnoreEngines) |
| `Malicious` | int | Cached **raw** VT malicious count |
| `Suspicious` | int | Cached **raw** VT suspicious count |
| `Undetected` | int | Cached **raw** VT undetected count |
| `Harmless` | int | Cached **raw** VT harmless count |
| `IgnoredEngines` | string | Engines applied to policy when the entry was written (semicolon-separated; empty if none). Fresh hits reuse the stored verdict; TTL refresh re-fetches VT and applies the **current** `IgnoreEngines` list. |
| `CachedAt` | string | When the cache entry was written (ISO 8601) |
| `Source` | string | Provenance of the cached verdict (currently always `VirusTotal`). Extending the vocabulary is **HMD-015**. |

Entries older than `CacheTtlDays` are ignored and refreshed on next miss.

### Field reference — `logs/download_index.csv`

| Field | Type | Meaning |
|-------|------|---------|
| `Url` | string | Requested URL |
| `LocalPath` | string | Path under `Downloaded/` on success; empty on failure |
| `FileName` | string | Staged file name |
| `Success` | bool | Download succeeded |
| `StatusCode` | int | HTTP status when known (`0` if unavailable) |
| `Attempts` | int | Attempts used (including retries) |
| `Bytes` | long | Bytes written on success |
| `ContentType` | string | Content-Type when known |
| `Error` | string | Error text on failure |
| `DownloadedAt` | string | ISO 8601 timestamp |

### Field reference — `logs/progress.log` (HMD-046)

Append-only UTF-8 text (oldest first). One line per event. Never contains
API keys. Parallel downloads emit per-URL ITEM lines **after** the pool
returns; process/deploy lines are live.

| Token | Meaning |
|-------|---------|
| ISO timestamp | Local `DateTime.ToString('o')` prefix |
| `PHASE=` | `Download` \| `Process` \| `Deploy` \| `Complete` |
| `STATUS=` | `START` \| `ITEM` \| `STEP` \| `DONE` |
| `N/M` | Current / total when a count is known |
| remainder | Human message (file leaf, verdict, ok/fail counts) |

`STEP` (Hash / Defender / VirusTotal / Archive) is log + progress bar only.
START / ITEM / DONE also `Write-Host` when `DisplayProgress` is true.

### Field reference — `logs/deploy_copy.csv` (HMD-019)

Written when `-DeployMapPath` is set. One row per **copy attempt** (a glob may
produce many rows; a miss produces one row for the pattern).

| Field | Type | Meaning |
|-------|------|---------|
| `File` | string | Map file key |
| `Destination` | string | Destination folder from the map |
| `SourcePath` | string | Path under `Clean/` (empty on miss) |
| `DestPath` | string | Final copy path (empty on miss/error) |
| `Status` | string | `Copied` \| `Miss` \| `Error` \| `SkippedExists` |
| `Error` | string | Error text when applicable |
| `CopiedAt` | string | ISO 8601 timestamp |

### Field reference — `checkpoint.json`

| Field | Type | Meaning |
|-------|------|---------|
| `UpdatedAt` | string | Last checkpoint write (ISO 8601) |
| `CompletedUrls` | string[] | URLs already fully processed; skipped on resume for the same `-WorkRoot` |

### Field reference — console JSON summary

| Field | Type | Meaning |
|-------|------|---------|
| `WorkRoot` | string | Absolute work-root path |
| `InputCount` | int | Unique URLs parsed from input |
| `QueuedCount` | int | URLs not already in the checkpoint at **start** of this run (download/process queue). Not “still unfinished after the run” — on a successful first pass it equals `InputCount` / `ProcessedCount` |
| `SkippedByCheckpoint` | int | `InputCount - QueuedCount` — URLs skipped by resume |
| `ProcessedCount` | int | Download results handled in this run (`0` if everything was checkpoint-skipped) |
| `CleanCount` / `SuspiciousCount` / `MaliciousCount` / `UnknownCount` / `ErrorCount` | int | **Verdict** tallies over **top-level** `Records` (archive members excluded) |
| `UndetectedSum` / `HarmlessSum` | int | Sum of per-record VT engine counts `Undetected` / `Harmless` over top-level `Records` |
| `DeployedCount` / `DeployMissCount` / `DeployErrorCount` / `DeploySkipCount` | int | Clean-deploy outcomes when `-DeployMapPath` is set (else `0`) |
| `DeployLog` | string \| null | Path to `logs/deploy_copy.csv` when deploy ran |
| `PrefixFileNames` | bool | Whether this run used the `NNNN_` staged-name prefix |
| `RecordsArePriorScanlog` | bool | `True` when this run processed nothing but returned existing scanlog / archive-scanlog rows |
| `ScanLog` | string | Path to `scanlog.csv` (top-level) |
| `ArchiveScanLog` | string | Path to `archive-scanlog.csv` (members; file present only when members exist) |
| `HashCache` | string | Path to `hashcache.csv` |
| `ProgressLog` | string \| null | Path to `logs/progress.log` when `ProgressLog` ran |
| `Report` | string \| null | Path to `report.html` when generated |
| `Records` | object[] | Combined top-level + archive-member rows (same columns) |

## Reporting

`reports/report.html` includes:

| Section | Content |
|---------|---------|
| KPIs | Counts per verdict on **top-level** files (archive members excluded) (HMD-047) |
| Inventory table | `URL`, `SHA256`, `Verdict`, `Malicious`, `Suspicious`, `Signature`, `Defender` (includes `#archive/` members) |

HTML inventory currently emphasizes malicious/suspicious counts, signature, and
Defender status; full Undetected values remain in `scanlog.csv` /
`archive-scanlog.csv` / console `Records`.

## Security considerations

- Quarantine **malicious** files (copy/move into `Quarantine/` and `Malicious/`)
- Optionally quarantine **suspicious** (`QuarantineSuspicious`)
- **Local Defender hard gate** before VT (HMD-026): threat → Malicious; scan
  unavailable/error → Error (do not treat as Clean). MOTW may trigger OS
  scanning but is **not** sufficient alone — HMD always requests an explicit scan
  when `LocalAvScanEnabled` is true.
- Validate Authenticode signatures (advisory; does not override VT malicious)
- Preserve evidence under work-root folders; do not auto-delete

## Folder structure (under `-WorkRoot`)

| Folder | Role |
|--------|------|
| `Downloaded` | Staging for raw downloads |
| `Clean` | VT clean |
| `Suspicious` | VT suspicious |
| `Malicious` | VT malicious |
| `Quarantine` | Isolated copies per policy |
| `Unknown` | No VT result / not found |
| `Error` | Download or processing failures |
| `logs` | CSV artefacts + `progress.log` |
| `reports` | HTML report |

## Configuration parameters

See [`config/hmd.defaults.json`](../config/hmd.defaults.json):

| Key | Meaning |
|-----|---------|
| `ApiDelaySeconds` | Delay between VT calls |
| `DownloadThreads` | Concurrent downloads (5–10 recommended) |
| `MaxFileBytes` | Size limit |
| `CacheTtlDays` | Hash cache TTL |
| `MaliciousThreshold` / `SuspiciousThreshold` | Verdict gates |
| `QuarantineMalicious` / `QuarantineSuspicious` | Quarantine policy |
| `UploadUnknownSamples` | Default false; CLI may override |
| `GenerateReport` | HTML report on completion |
| `DisplaySummary` | Write host summary block after the run (default true) |
| `DisplayScanLog` | Write top-level `scanlog.csv` table to host after the run (default true) |
| `DisplayArchiveScanLog` | Write `archive-scanlog.csv` table to host (default **false**; HMD-047) |
| `DisplayProgress` | Live `Write-Progress` bar + host START/ITEM/DONE lines (default true) (HMD-046) |
| `ProgressLog` | Append `logs/progress.log` during the run (default true) (HMD-046) |
| `PrefixFileNames` | Prefix staged names with `NNNN_` (default true); `-NoFileNamePrefix` forces false |
| `DeployOverwrite` | When deploying Clean files, overwrite existing destination files (default true) |
| `LocalAvScanEnabled` | Run Microsoft Defender custom scan after download (default true); `-SkipLocalAvScan` forces false |
| `LocalAvProvider` | Local scanner id (currently `Defender` only) |
| `ArchiveInspectionEnabled` | Extract ZIP-family archives after container triage (default false) (HMD-006) |
| `ArchiveContentsHashOnly` | Legacy: true→`ArchiveVtMode` None, false→All when `ArchiveVtMode` unset (default true) |
| `ArchiveVtMode` | Member VT: `None` \| `All` \| `Interesting` (default `None`) (HMD-045) |
| `ArchiveInterestingExtensions` | Extensions treated as interesting for selective VT |
| `ArchiveInterestPathKeywords` | Path substrings (e.g. `bin/`) marking interesting members |
| `ArchiveInterestCheckMz` | Treat MZ/PE magic as interesting (default true) |
| `ArchiveMaxMembers` | Cap on file entries extracted per archive (default 500) |
| `ArchiveExtensions` | Extensions treated as ZIP-family (default `.zip`/`.jar`/`.hpi`/`.jpi`) |
| `IgnoreEngines` | VT engine names excluded from policy verdict counts (default `[]`) |
| `MaxDownloadRetries` | Retry count for transient download errors |
| `AnalysisPollSeconds` / `AnalysisPollMaxAttempts` | Upload analysis poll |
| `InboxRoot` / `WorkRootBase` | Optional defaults for inbox worker paths (CLI still primary) |
| `InboxMutexName` | Named mutex (default `Local\Hash.MassDownloader.Inbox`) |
| `InboxMutexTimeoutMs` | Wait before fail-closed (default `0`) |
| `ApiKeyCredentialTarget` | CredMan generic target (default `Hash.MassDownloader/VirusTotal`) |

`-AgentSummary` on `scripts/Invoke-HmdBulkDownload.ps1` emits one success-stream
line (`HMD-RUN-OK …` / `HMD-RUN-FAIL …`) and turns off `DisplaySummary` /
`DisplayScanLog` / `DisplayArchiveScanLog` / `DisplayProgress` unless those keys
are set in `ConfigOverride`. `ProgressLog` still writes `logs/progress.log`
unless explicitly set false.

`-DeployMapPath` accepts a sectioned TXT (`@destination` then file names) or CSV
(`Destination,File`). `File` may be exact, a wildcard, or an `http(s)` URL.
Wildcards use PowerShell **`-like`** (not regex): `*` = any sequence, `?` = one
character; matching is case-insensitive. Examples: `*.pgi`, `file?.dll`. Only
`*` / `?` enable glob mode (no `[a-z]` character classes). A glob copies **all**
matching Clean files (one `deploy_copy.csv` row each). `http(s)` entries are
**harvested** into the download queue and matched by full URL (dest leaf = URL
path leaf). `-InputPath` may be omitted when the map has ≥1 such URL. See
`examples/deploy.sample.txt` / `.csv` and issues **HMD-019** / **HMD-023** /
**HMD-027**.

## Error handling matrix

| Condition | Behaviour |
|-----------|-----------|
| HTTP 404 | Record error; no retry storm |
| HTTP 403 | Record error; no retry |
| HTTP 429 | Back off (delay × factor); retry within limit |
| Transient 5xx / network | Retry with backoff |
| Processing exception | Isolate to `Error/`; continue batch |

## Future roadmap

### Phase 1 — unattended + desktop input

- Inbox serial worker + Windows Scheduled Task (`HMD-028`) — **done in v0.5.0**
- Unattended secrets / CredMan (`HMD-034`); mutex + inbox lifecycle (`HMD-035`) — **done in v0.5.0**
- PowerShell GUI for supplying input files (`HMD-029`) — still open

### Phase 2 — web + directory ACL

- Web front-end and modern back-end (`HMD-030`)
- AD group and/or Entra ID SSO (`HMD-031`)
- Allowed download locations and output folders per AD group (`HMD-032`)

### Phase 3 — IdP breadth + ops gaps

- Other popular IdPs (`HMD-033`); SCIM provisioning (`HMD-043`)
- Job history / retention / evidence export (`HMD-036`)
- Notifications / webhooks (`HMD-037`)
- Network egress allowlist / proxy (`HMD-038`)
- Air-gapped / offline reputation (`HMD-039`)
- HA multi-node workers (`HMD-040`)
- Container / Kubernetes packaging (`HMD-041`)
- Malicious-override approval workflow (`HMD-042`)
- Intune / PS 5.1 dual-host (`HMD-044`)

### Other roadmap (unphased)

- SQLite cache (`HMD-005`)
- Extend `hashcache.Source` / alternate reputation providers (`HMD-015`)
- SIEM / enterprise reporting (`HMD-007`)

## Related product artefacts

- Issues: [`issues.md`](issues.md)
- Changelog: [`../CHANGELOG.md`](../CHANGELOG.md)
- Entry script: `scripts/Invoke-HmdBulkDownload.ps1`
