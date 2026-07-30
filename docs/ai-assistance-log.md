# AI assistance log — Hash.MassDownloader

Human-readable disclosure trail for substantive AI-assisted work.

| When | Phase / scope | Deliverable | Tool / model | Purpose | Verified by |
|------|---------------|-------------|--------------|---------|-------------|
<!-- AAI+ -->
| 2026-07-30 06:59:00 | HMD-023 globs + HMD-020–022 backlog | deploy wildcards; dry-run/Sha256/rename stories; Pester 24 | Cursor Agent [Tier 2: composer-2.5-fast] | Plugins `*.pgi` to one folder, exe to another | Operator: `Invoke-HmdValidate.ps1 -AgentSummary` → HMD-VALIDATE-OK |
| 2026-07-29 22:15:00 | HMD-018/019 prefix + Clean deploy | optional PrefixFileNames; DeployMapPath copy+dirs; samples; Pester 21 | Cursor Agent [Tier 2: composer-2.5-fast] | Operator: optional leaf names + post-Clean distribute | Operator: `Invoke-HmdValidate.ps1 -AgentSummary` → HMD-VALIDATE-OK |
| 2026-07-29 20:12:00 | HMD-017 QueuedCount rename | summary property + agent token + brief | Cursor Agent [Tier 2: composer-2.5-fast] | Avoid “pending leftover” misread on final report | Operator: `Invoke-HmdValidate.ps1 -AgentSummary` → HMD-VALIDATE-OK |
| 2026-07-29 06:30:00 | HMD-016 product rename | Hash.MassDownloader identity; HMD-* issues; OSS-020 | Cursor Agent [Tier 2: composer-2.5-fast] | Scanner-agnostic name before public repo; VT stays first provider | Operator: `Invoke-HmdValidate.ps1 -AgentSummary` → HMD-VALIDATE-OK |
| 2026-07-29 05:23:30 | HMD-013 display + AgentSummary | defaults, entry script, module display, tests quiet | Cursor Agent [Tier 2: composer-2.5-fast] | Post-run summary/scanlog config; agent one-liner | Operator: `Invoke-HmdValidate.ps1 -AgentSummary` |
| 2026-07-28 16:36:00 | v0.1 scaffold + MVP | product brief, module, tests, validate trio | Cursor Agent [Tier 2: composer-2.5-fast] | Convert draft specs; implement PS7 bulk downloader with mocked VT | Operator: run `Invoke-HmdValidate.ps1 -AgentSummary` |
