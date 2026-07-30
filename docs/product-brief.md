# Hash-Assisted Bulk File Downloader

Comprehensive technical specification and design document for **Hash.MassDownloader**
(`Hmd` prefix, issue IDs `HMD-*`).

**Host floor:** PowerShell 7.2+  
**License:** MIT  
**Status:** v0.1 MVP implements the core pipeline; roadmap items below are documented only.

---

## Executive summary

PowerShell-based bulk downloader with SHA256-first hash reputation triage
(VirusTotal is the v0.1 provider; naming is scanner-agnostic for HMD-015),
optional file submission, quarantine handling, reporting, audit logging, and
resume capabilities.

## Business objectives

- Reduce manual malware triage
- Automate reputation checks
- Provide auditable results
- Minimize VirusTotal API consumption through SHA256-first lookups and local caching

## Scope

| In scope | Out of scope (v0.1) |
|----------|---------------------|
| TXT and CSV URL input | SQLite cache |
| Parallel downloads (5–10) | Archive inspection (HPI/JPI/JAR) |
| SHA256 calculation | SIEM integration |
| VirusTotal API v3 (hash lookup; upload opt-in) | Scheduling |
| Authenticode advisory validation | Enterprise reporting packs |
| Quarantine workflows | Intune / PS 5.1 dual-host |
| Logging, HTML reporting, resume | GitHub publish (operator choice) |

## Architecture overview

A **download layer** performs parallel downloads while a **processing layer**
performs serialized VirusTotal operations to respect API quotas. Cache,
checkpoint, and reporting services persist state.

```text
Input (TXT/CSV)
    → Download pool (concurrent)
    → Downloaded/
    → SHA256
    → Hash cache (TTL) ──hit──→ Classify
              │ miss
              ↓
         VT API (serialized)
              ↓
    Clean / Suspicious / Malicious / Quarantine / Unknown / Error
              ↓
    logs/*.csv + reports/report.html + checkpoint.json
```

## Functional requirements

1. **Input handling** — TXT (one URL per line; whitespace-separated URLs on a
   single line are split) and CSV (column `Url` or first column)
2. **Retry logic** — transient HTTP failures; explicit handling for 404, 403, 429
3. **Content-type validation** — soft check (warn / record; do not hard-fail by default)
4. **Size limits** — skip or error when `Content-Length` or downloaded bytes exceed config
5. **Hash calculation** — SHA256 of each successfully downloaded file
6. **Duplicate detection** — same URL or same SHA256 within a run / cache
7. **VT lookup** — SHA256-first `GET /api/v3/files/{hash}`
8. **VT upload fallback** — when hash unknown and `-UploadUnknownSamples` enabled
9. **Verdict classification** — from `last_analysis_stats` + policy thresholds
10. **HTML reporting** — KPIs, detection summaries, file inventory
11. **Resume support** — checkpoint after each processed URL; skip completed on restart
12. **Optional filename prefix** — `NNNN_` index prefix on staged names (`PrefixFileNames`;
    `-NoFileNamePrefix` to use the URL leaf)
13. **Clean deploy** — optional map-driven copy of Clean files to destinations
    (`-DeployMapPath`; create folders; keep `Clean/` as audit copy; `*` / `?`
    wildcards expand to all matches)

## Non-functional requirements

| NFR | Expectation |
|-----|-------------|
| Reliability | Isolate per-URL failures; continue batch |
| Maintainability | Module + Safety-tier entry scripts; Pester + PSA |
| Auditability | CSV scan log, hash cache, download index |
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

| Verdict | Rule (v0.1) |
|---------|-------------|
| **Malicious** | `Malicious >= MaliciousThreshold` (default 1) |
| **Suspicious** | Else `Suspicious >= SuspiciousThreshold` (default 1) |
| **Clean** | Else hash **known** on VT with zero malicious and zero suspicious (Undetected / Harmless may be &gt; 0) |
| **Unknown** | Hash not found and upload disabled or upload/analysis failed |
| **Error** | Download or processing failure (see `Error` field) |

**Undetected does not drive the verdict** by itself. A high Undetected count with
zero Malicious/Suspicious supports **Clean**; Undetected `0` with verdict
**Unknown** usually means “no VT report,” not “all engines clean.”

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
| `logs/scanlog.csv` | Per-file processing record (primary audit trail) |
| `logs/hashcache.csv` | Persistent hash → verdict cache |
| `logs/download_index.csv` | Download attempt outcomes |
| `checkpoint.json` | Resume set (completed URLs) |
| Console JSON | Summary object from `Invoke-HmdBulkDownload` / entry script |
| `reports/report.html` | Human-readable KPIs + inventory |

### Field reference — `logs/scanlog.csv` (and console `Records[]`)

| Field | Type | Meaning |
|-------|------|---------|
| `Url` | string | Source URL processed |
| `FileName` | string | Staged name: `NNNN_` + leaf when `PrefixFileNames` is true (default); else sanitized URL leaf (collision → `name_Index.ext`) |
| `LocalPath` | string | Final path after disposition (Clean / … / Error), or empty on early failure |
| `Sha256` | string | Lowercase hex SHA-256 of the downloaded bytes; empty if download failed |
| `Verdict` | string | `Clean` \| `Suspicious` \| `Malicious` \| `Unknown` \| `Error` |
| `Malicious` | int | VT engines marking malicious (`0` if no VT report) |
| `Suspicious` | int | VT engines marking suspicious (`0` if no VT report) |
| `Undetected` | int | VT engines that scanned with **no** detection (`0` if no VT report) |
| `Harmless` | int | VT engines that explicitly marked harmless (`0` if no VT report; older CSV rows without the column normalize to `0` on load) |
| `SignatureStatus` | string | `Get-AuthenticodeSignature` status (advisory). Often `UnknownError` / not applicable for non-PE assets (`.ico`, raw `.bin`) |
| `Signer` | string | Signer certificate subject when present; else empty |
| `ContentType` | string | HTTP Content-Type when observed (soft metadata) |
| `Bytes` | long | Downloaded size in bytes |
| `CacheHit` | bool | `True` only when **this processing pass** reused a fresh `hashcache.csv` entry instead of calling VT. `False` on first VT lookup/write. Unchanged historical rows in `scanlog.csv` keep their original value when a later run only resumes via checkpoint. |
| `Error` | string | Failure message; empty on success |
| `ProcessedAt` | string | Local timestamp (ISO 8601) when the row was finalized |

### Field reference — `logs/hashcache.csv`

| Field | Type | Meaning |
|-------|------|---------|
| `Sha256` | string | Cache key (lowercase hex) |
| `Verdict` | string | Cached disposition verdict |
| `Malicious` | int | Cached VT malicious count |
| `Suspicious` | int | Cached VT suspicious count |
| `Undetected` | int | Cached VT undetected count |
| `Harmless` | int | Cached VT harmless count |
| `CachedAt` | string | When the cache entry was written (ISO 8601) |
| `Source` | string | Provenance of the cached verdict (v0.1: always `VirusTotal`). Extending the vocabulary is **HMD-015**. |

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
| `CleanCount` / `SuspiciousCount` / `MaliciousCount` / `UnknownCount` / `ErrorCount` | int | **Verdict** tallies over `Records` (`Verdict` column — not VT engine fields) |
| `UndetectedSum` / `HarmlessSum` | int | Sum of per-record VT engine counts `Undetected` / `Harmless` over `Records` |
| `DeployedCount` / `DeployMissCount` / `DeployErrorCount` / `DeploySkipCount` | int | Clean-deploy outcomes when `-DeployMapPath` is set (else `0`) |
| `DeployLog` | string \| null | Path to `logs/deploy_copy.csv` when deploy ran |
| `PrefixFileNames` | bool | Whether this run used the `NNNN_` staged-name prefix |
| `RecordsArePriorScanlog` | bool | `True` when this run processed nothing but returned existing `scanlog.csv` rows |
| `ScanLog` | string | Path to `scanlog.csv` |
| `HashCache` | string | Path to `hashcache.csv` |
| `Report` | string \| null | Path to `report.html` when generated |
| `Records` | object[] | Same shape as `scanlog.csv` rows (see above) |

## Reporting

`reports/report.html` includes:

| Section | Content |
|---------|---------|
| KPIs | Counts per verdict (`Clean`, `Suspicious`, `Malicious`, `Unknown`, `Error`) |
| Inventory table | `URL`, `SHA256`, `Verdict`, `Malicious`, `Suspicious`, `Signature` (Authenticode status) |

HTML inventory currently emphasizes malicious/suspicious counts and signature
status; full Undetected values remain in `scanlog.csv` / console `Records`.

## Security considerations

- Quarantine **malicious** files (copy/move into `Quarantine/` and `Malicious/`)
- Optionally quarantine **suspicious** (`QuarantineSuspicious`)
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
| `logs` | CSV artefacts |
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
| `DisplayScanLog` | Write `scanlog.csv` table to host after the run (default true) |
| `PrefixFileNames` | Prefix staged names with `NNNN_` (default true); `-NoFileNamePrefix` forces false |
| `DeployOverwrite` | When deploying Clean files, overwrite existing destination files (default true) |
| `MaxDownloadRetries` | Retry count for transient download errors |
| `AnalysisPollSeconds` / `AnalysisPollMaxAttempts` | Upload analysis poll |

`-AgentSummary` on `scripts/Invoke-HmdBulkDownload.ps1` emits one success-stream
line (`HMD-RUN-OK …` / `HMD-RUN-FAIL …`) and turns off `DisplaySummary` /
`DisplayScanLog` unless those keys are set in `ConfigOverride`.

`-DeployMapPath` accepts a sectioned TXT (`@destination` then file names) or CSV
(`Destination,File`). `File` may be exact or a wildcard. Wildcards use PowerShell
**`-like`** (not regex): `*` = any sequence, `?` = one character; matching is
case-insensitive. Examples: `*.pgi`, `file?.dll`. Only `*` / `?` enable glob mode
(no `[a-z]` character classes). A glob copies **all** matching Clean files (one
`deploy_copy.csv` row each). See `examples/deploy.sample.txt` / `.csv` and issues
**HMD-019** / **HMD-023**.

## Error handling matrix

| Condition | Behaviour |
|-----------|-----------|
| HTTP 404 | Record error; no retry storm |
| HTTP 403 | Record error; no retry |
| HTTP 429 | Back off (delay × factor); retry within limit |
| Transient 5xx / network | Retry with backoff |
| Processing exception | Isolate to `Error/`; continue batch |

## Future roadmap

- SQLite cache
- Extend `hashcache.Source` vocabulary / alternate reputation providers (`HMD-015`)
- Archive inspection for HPI/JPI/JAR
- SIEM integration
- Scheduling
- Enterprise reporting

## Related product artefacts

- Issues: [`issues.md`](issues.md)
- Changelog: [`../CHANGELOG.md`](../CHANGELOG.md)
- Entry script: `scripts/Invoke-HmdBulkDownload.ps1`
