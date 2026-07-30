# Release pipeline — Hash.MassDownloader

Operator / agent checklist for SemVer tags and GitHub Releases.
Does **not** replace Stream (VM) for git commit/push/tag — this doc defines
**what must be true before** those steps.

## Version surfaces (must stay aligned)

| Surface | Path / field |
|---------|----------------|
| Module manifest | `src/Hash.MassDownloader/Hash.MassDownloader.psd1` → `ModuleVersion` (+ `ReleaseNotes`) |
| HTTP User-Agent (defaults) | `config/hmd.defaults.json` → `UserAgent` = `Hash.MassDownloader/X.Y.Z` |
| Download fallback default | `src/Hash.MassDownloader/Private/Hmd.Download.ps1` → `-UserAgent` default |
| Product brief Status | `docs/product-brief.md` → `**Status:** vX.Y.Z — …` |
| Scope heading | `docs/product-brief.md` → `### In scope (vX.Y.Z)` |
| Changelog | `CHANGELOG.md` — move `[Unreleased]` into `## [X.Y.Z] - YYYY-MM-DD` |

Historical section titles under `## [0.1.0]` in CHANGELOG / AAI rows stay as-is.

## Before commit / push (required)

1. **Bump version strings** (do this **before** staging the release commit):

   ```powershell
   pwsh -NoProfile -File .\scripts\Invoke-HmdBumpVersion.ps1 `
     -Version 0.2.1 `
     -ReleaseNotes 'v0.2.1 — short summary of the release.' `
     -StatusSuffix 'core pipeline plus optional name prefix and Clean deploy; remaining roadmap items below are documented only.'
   ```

   Preview: add `-WhatIf`. Sync check only: `-CheckOnly -AgentSummary`.

2. **Edit CHANGELOG** — promote Unreleased notes into the new version section;
   leave a fresh empty `[Unreleased]` stub.

3. **Validate**:

   ```powershell
   pwsh -NoProfile -File .\scripts\Invoke-HmdValidate.ps1 -AgentSummary
   # → includes version sync (HMD-BUMP-CHECK-OK) then Pester + PSA
   ```

4. **Commit** (Stream / VM) — include bumped files + CHANGELOG + any feature
   work for the release. Commit message focuses on why (release X.Y.Z / fix …).

5. **Tag + push** — annotated tag `vX.Y.Z` on the release commit; push `main`
   and the tag; create GitHub Release from the tag notes / CHANGELOG section.

## Agent reminder

When the user asks to **release**, **tag**, or **publish**:

1. Run `Invoke-HmdBumpVersion.ps1` for the target SemVer **first** (unless
   `-CheckOnly` already reports OK for that version).
2. Then CHANGELOG promotion → validate → commit → tag → push → Release.

Skipping step 1 is what left `UserAgent` at `/0.1` after the v0.2.0 ship.

## Related

- Issue **HMD-024** (release version bump gate)
- Entry validate: `scripts/Invoke-HmdValidate.ps1`
- Spec: [product-brief.md](product-brief.md)
