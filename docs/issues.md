# Issues — Hash.MassDownloader

Product issue register. IDs are stable (`HMD-NNN`). Newest first.

## Done

Shipped features (Status `done`). Newest first. On release, move completed
items here from **Backlog** (see [release.md](release.md)).

| ID | Title | Status | Notes |
|----|-------|--------|-------|
| HMD-028 | Inbox worker + Scheduled Task | done | v0.5.0; `Invoke-HmdInboxWorker`; Plan `07452bed` |
| HMD-034 | Unattended secrets / CredMan API key | done | v0.5.0; target `Hash.MassDownloader/VirusTotal` |
| HMD-035 | Single-instance mutex + inbox lifecycle | done | v0.5.0; Plan `07452bed` |
| HMD-045 | Selective VT for interesting archive members | done | ArchiveVtMode Interesting; see notes |
| HMD-006 | Archive inspection (HPI/JPI/JAR) | done | ZIP-family; hash-only default; see notes |
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
| HMD-044 | Intune / PS 5.1 dual-host | backlog | Phase 3+; see notes |
| HMD-043 | SCIM provisioning | backlog | Phase 3; pairs with HMD-031/033; see notes |
| HMD-042 | Malicious-override approval workflow | backlog | Phase 2–3; see notes |
| HMD-041 | Container / Kubernetes packaging | backlog | Phase 3; see notes |
| HMD-040 | HA multi-node workers | backlog | Phase 3; see notes |
| HMD-039 | Air-gapped / offline reputation mode | backlog | Phase 3; see notes |
| HMD-038 | Network egress allowlist / proxy policy | backlog | Phase 3 gap; see notes |
| HMD-037 | Notifications / webhooks on job complete | backlog | Phase 3 gap; see notes |
| HMD-036 | Job history, retention, evidence export | backlog | Phase 3 gap; see notes |
| HMD-033 | Access control — other popular IdPs | backlog | Phase 3; Okta / Keycloak / Auth0 / …; see notes |
| HMD-032 | Allowed download locations + output folders per AD group | backlog | Phase 2; path ACL by group; see notes |
| HMD-031 | Access control — AD group and/or Entra ID (SSO) | backlog | Phase 2; see notes |
| HMD-030 | Web front-end + modern back-end | backlog | Phase 2; see notes |
| HMD-029 | PowerShell GUI for supplying input files | backlog | Phase 1; see notes |
| HMD-025 | FP-aware VT verdict policy (threshold + engine ignore) | done | ChromeDriver VirIT `Win95.Marburg`; see notes |
| HMD-023 | Deploy-map globs / wildcards (`*.pgi`) | done | `*` / `?` via `-like`; expands to all Clean matches; Miss if zero |
| HMD-022 | Deploy-map explicit rename (`tool.exe → app.exe`) | backlog | Dest leaf differs from source leaf |
| HMD-021 | Deploy-map match by Sha256 / Url columns | backlog | CSV (and optional TXT) keys beyond FileName |
| HMD-020 | Clean-deploy dry-run | backlog | Preview copies without writing; log Status=WouldCopy |
| HMD-019 | Copy Clean files to mapped destinations | done | Sectioned TXT + CSV map; create dirs; copy+audit CSV; unmatched warn |
| HMD-018 | Optional `NNNN_` download filename prefix | done | Config `PrefixFileNames` (default true); `-NoFileNamePrefix`; collision disambiguation |
| HMD-015 | Extend `hashcache.Source` beyond VirusTotal | backlog | Controlled vocabulary + optional providers; see candidates in issue notes |
| HMD-005 | SQLite hash cache | backlog | Roadmap |
| HMD-007 | SIEM / enterprise reporting (scheduling → HMD-028) | backlog | Roadmap; scheduler slice moved to HMD-028 |

## Notes

### HMD-006 notes — archive inspection (HPI/JPI/JAR)

**Intent:** When a downloaded file is a ZIP-family archive (Jenkins `.hpi` /
`.jpi`, Java `.jar`, and plain `.zip`), open it safely and triage **member**
payloads — not only the container hash.

**Acceptance (confirmed 2026-07-31):**

1. Detect by extension: `.hpi`, `.jpi`, `.jar`, `.zip` (case-insensitive).
2. Config: `ArchiveInspectionEnabled` (default **false**),
   `ArchiveContentsHashOnly` (default **true** — members get SHA-256 only; no VT),
   `ArchiveMaxMembers`, `ArchiveExtensions`. Depth **1** only (no nested recurse).
3. After container SHA-256 + local AV (+ optional container VT), extract under
   `Inspected/<parentLeaf>/` with **zip-slip** rejection.
4. Per member: SHA-256; child scanlog row (`FileName` = `#archive/<entry>`);
   when `ArchiveContentsHashOnly` is **false**, VT hash lookup like top-level.
5. With hash-only (default): parent verdict unchanged by members (except extract
   failure → parent `Error`). With VT on members: parent = worst of container +
   members. Quarantine/deploy apply to the **container** only (skip `#archive/`
   rows for Clean deploy and summary KPIs).
6. Pester: zip-slip reject, member hash rows, disabled-by-default, hash-only
   default, depth-1 only.
7. Out of scope v1: nested archive recurse, RAR/7z/cab, member Clean-deploy;
   **selective** member VT by interest heuristics → **HMD-045**.

### HMD-045 notes — selective VT for interesting archive members

**Intent:** Complement HMD-006: after extract + member SHA-256, classify
members that matter from a vulnerability POV and run VT hash lookup **only**
on that subset — save API quota vs full-member VT (`ArchiveContentsHashOnly`
false).

**Depends on:** HMD-006 (inspection + `#archive/` scanlog rows).

**Acceptance (confirmed 2026-07-31):**

1. Config mode alongside HMD-006 toggles: `ArchiveVtMode` `None` \| `All` \|
   `Interesting` (map existing `ArchiveContentsHashOnly` → None/All for
   back-compat when mode unset).
2. **Interesting** heuristics (v1, config lists): high-risk extensions
   (`.exe`, `.dll`, `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.msi`, `.scr`,
   `.com`, `.sys`, nested `.jar` / `.hpi` / `.jpi` leaf, etc.); optional MZ/PE
   magic; optional path keywords (`bin/`, `lib/`, `plugins/`).
3. Non-interesting members: SHA-256 + scanlog only (same as hash-only today).
4. Interesting members: VT hash lookup like top-level; parent worst-of when
   any member VT runs.
5. Scanlog/report flag why a member was selected (`ArchiveInterestReason`).
6. Pester: interesting → VT called; boring → not; mode None/All unchanged.
7. Out of scope v1: ML/YARA, nested recurse, uploading unknown hashes (hash
   lookup only).

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

### HMD-028–029 notes — Phase 1 (unattended + GUI)

**HMD-028 — Inbox watcher + serial queue + Scheduled Task**

1. Watch a configured **input folder** for new URL-list drops (TXT/CSV).
2. **Queue** arrivals; process **one job at a time** (no overlapping
   `Invoke-HmdBulkDownload` runs).
3. Phase 1 host trigger: **Windows Scheduled Task** (poll or short-lived
   watcher invocation) — not a always-on Windows Service yet.
4. Move or rename completed inputs (exact inbox lifecycle → **HMD-035**).
5. Supersedes the vague “Scheduling” slice of **HMD-007** (SIEM / enterprise
   reporting remain on HMD-007).

**Optional deploy sidecar:** beside `{stem}.txt` / `{stem}.csv` in `incoming/`,
drop `{stem}.deploy.txt` or `{stem}.deploy.csv`. The worker claims both, passes
`-DeployMapPath` into `Invoke-HmdBulkDownload`, and moves both to `done/` or
`failed/`. Prefer `.deploy.txt` when both exist. Orphan sidecars are ignored.
Sample: `examples/inbox/urls.txt` + `urls.deploy.txt`.

**HMD-029 — PowerShell GUI for input**

1. Small **PS GUI** (WinForms or WPF) to pick/paste URL lists, optional deploy
   map, output root, and common switches.
2. Writes a validated input file into the inbox (or invokes the module
   directly for interactive runs).
3. Does not replace the CLI entry script; operators who prefer CLI keep it.

**Phase 1 companions (filed as gap stories):** **HMD-034** (secrets for the
task identity), **HMD-035** (mutex + processed/failed folders).

**Active plan (HMD-028 + 034 + 035):** config workspace
`plans/2026-07-31_hmd-phase1-inbox-watcher_07452bed.plan.md` (**OSS-021**).
GUI **HMD-029** deferred to a later plan.

### HMD-030–032 notes — Phase 2 (web + enterprise ACL)

**HMD-030 — Web front-end + modern back-end**

1. Browser UI for job submit, status, reports, and deploy-map editing.
2. Modern back-end (API + worker) wrapping the existing PowerShell pipeline
   or a ported core — stack TBD in plan (ASP.NET / FastAPI / etc.).
3. Depends on durable queue semantics from Phase 1 (HMD-028/035).

**HMD-031 — AD / Entra ID (SSO)**

1. Authenticate operators via **Active Directory group** membership and/or
   **Microsoft Entra ID** with SSO (OIDC/SAML).
2. Map identity → roles (operator / admin / read-only) before any download
   or deploy action.

**HMD-032 — Path ACL per AD group**

1. Per-group allowlists for **download URL prefixes / hosts** and **output /
   deploy destination folders**.
2. Deny-by-default outside the allowlist; audit every rejection.
3. Aligns with Clean-deploy maps (HMD-019+) so deploy destinations cannot
   escape group policy.

### HMD-033 notes — Phase 3 IdP expansion

Beyond AD/Entra: support other common enterprise IdPs (candidates: **Okta**,
**Keycloak**, **Auth0**, **Ping**, **Google Workspace**). Prefer a pluggable
OIDC/SAML layer rather than one-off connectors. **SCIM** provisioning →
**HMD-043**.

### HMD-034–038 notes — Phase 3 / gap backlog (“what was forgotten”)

Filed after Phase 1–2 brainstorm; several are **Phase 1–2 companions** even
though numbered after HMD-033.

| ID | Why it matters |
|----|----------------|
| **HMD-034** | Scheduled Task / service account must load VT API key (and later IdP secrets) via **Credential Manager**, DPAPI, or **Managed Identity** — not plaintext env on disk |
| **HMD-035** | Named mutex / lock file so GUI + task + CLI cannot double-run; inbox `incoming` → `processing` → `done`/`failed` |
| **HMD-036** | Persist job history, report retention, and **evidence export** (zip of scanlog + HTML + checkpoint) for audits |
| **HMD-037** | Email / Teams / webhook on job complete or Malicious quarantine |
| **HMD-038** | Egress **proxy** and **URL host allowlist** at network layer (complements HMD-032 folder ACL) |

### HMD-039–044 notes — extended roadmap (formerly “not filed”)

| ID | Intent |
|----|--------|
| **HMD-039** | **Air-gapped / offline reputation** — run without live VT: local hashcache + Defender (+ optional offline intel feeds); clear UI/scanlog when cloud lookup skipped; no silent “Unknown = Clean” |
| **HMD-040** | **HA multi-node workers** — shared durable queue, sticky job ownership, no double-process; builds on HMD-028/035; Phase 2 API may stay single-node first |
| **HMD-041** | **Container / Kubernetes packaging** — image + Helm/Kustomize (or Compose) for the Phase 2 back-end/worker; document volume mounts for inbox/output/cache; secrets via K8s secrets / MI |
| **HMD-042** | **Malicious-override approval** — two-person or role-gated workflow to release/deploy a Malicious/Suspicious sample with full audit (who, why, expiry); complements HMD-025 IgnoreEngines (policy ≠ human override) |
| **HMD-043** | **SCIM provisioning** — sync users/groups from Entra (or other IdP) into HMD roles / HMD-032 path ACL bindings; optional after HMD-031 |
| **HMD-044** | **Intune / PS 5.1 dual-host** — ship constrained entry/remediation stubs for Windows PowerShell 5.1 + Intune (size/host floors like WinGet.Audit); core module remains PS 7.2+ |

**Still not filed:** mobile UI (discuss if needed).

