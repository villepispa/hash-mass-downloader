# Example inbox drop (copy these into `<InboxRoot>/incoming/`)

| File | Role |
|------|------|
| `urls.txt` | URL list (TXT or CSV) — claimed as the job |
| `urls.deploy.txt` | Optional Clean-deploy map for the same stem |

Naming rule: if the input is `{stem}.txt` or `{stem}.csv`, the sidecar must be
`{stem}.deploy.txt` or `{stem}.deploy.csv` in the **same** `incoming/` folder.
When both sidecars exist, `.deploy.txt` wins. Orphan `*.deploy.*` files (no
matching input) are **not** claimed.

After a successful run both files move to `done/`; on failure, to `failed/`.
