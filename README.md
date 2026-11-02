# C131 — Querybook: Python cell result endpoints skip DataDoc ACL (sibling authz IDOR)

**Status:** CONFIRMED — NOT submitted (await user approval)  
**Platform / program:** Bugcrowd — Pinterest (`pinterest`)  
**Asset:** Open source projects (non-forked) at `github.com/pinterest/` → `pinterest/querybook`  
**Bounty range (program):** ~$200–$25,000  
**Target fingerprint:** `pinterest/querybook@ebd3e63ac0153af0df0f3f842f35b263b0d10d59` (origin/master as of 2026-11-02)  
**Component:** `querybook/server/datasources/python_cell.py` vs `datadoc.py` / `datadoc_collab.py`  
**Class:** Sibling-endpoint authorization inconsistency / IDOR (CWE-639 / CWE-863)  
**Severity:** High (P2) — env peer without DataDoc read/write can read and overwrite private Python cell outputs  
**CVSS 3.1 (proposed):** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N → **7.1 High**

## Summary

Querybook DataDocs enforce per-document ACLs (`assert_can_read` / `assert_can_write` via owner, public flag, or `DataDocEditor`). Sibling REST endpoints for **Python cell results** only call `verify_data_cell_permission`, which checks **environment membership** (and safe query-engine access) — **not** DataDoc ACL.

Any authenticated user who shares an Environment with the victim can:

1. **Read** private notebook Python cell outputs (JSON / DataFrame / image payloads that may contain query-result extracts, PII, or secrets printed in cells).
2. **Overwrite** those outputs so the owner/editors see attacker-controlled content (integrity / misleading analysis; image type rendered as `<img src={data}>`).

Sibling controls prove intent: `GET /ds/datadoc/<id>/` returns `403 CANNOT_READ_DATADOC` and `PUT /ds/data_cell/<id>/` returns `401 CANNOT_WRITE_DATADOC` for the same peer, while `/ds/python_cell/<id>/result/` succeeds.

## Root cause

| Endpoint | Authz |
|---|---|
| `GET/PUT /ds/datadoc/<id>/` | `assert_can_read` / `assert_can_write` (+ env) |
| `PUT /ds/data_cell/<cell_id>/` | `assert_can_write` via `datadoc_collab.update_data_cell` |
| `GET /ds/python_cell/<cell_id>/result/` | **only** `verify_data_cell_permission` |
| `PUT /ds/python_cell/<cell_id>/result/` | **only** `verify_data_cell_permission` |

`verify_data_cell_permission` (permission.py) resolves the cell’s DataDoc `environment_id` and calls `verify_environment_permission` — membership only. It never calls `assert_can_read` / `assert_can_write`.

Python cells were added in #1559 (`32bcdd85`); the result API appears to have reused the weaker cell-execution permission helper instead of DataDoc ACL.

## Prerequisites

- Authenticated Querybook user.
- Membership in the same Environment as the victim DataDoc (common in shared team envs).
- Knowledge of `cell_id` (autoincrement integer; predictable / enumerable; may also appear in URLs, logs, shared boards, or UI network traffic when a privileged user opens the doc).

## Impact

- **Confidentiality (High):** Leak private DataDoc Python outputs, including DataFrames sourced from query executions via client `get_df`, printed secrets, analysis results.
- **Integrity (Low–Medium):** Persist forged stdout/stderr/image/json for the cell; owner UI shows attacker content.
- **Not** browser RCE: Pyodide runs client-side; this is a server ACL bypass on stored results.

## Local reproduction (authz-layer e2e)

Fixture: private non-shareable Environment; Owner A private DataDoc + Python cell with secret JSON output; Peer B in same env, **no** editor grant.

```
peer GET /ds/datadoc/1/                 → 403 CANNOT_READ_DATADOC
peer GET /ds/python_cell/1/result/      → 200 + secret PII-TOKEN-AABB
peer PUT /ds/python_cell/1/result/      → 200 (forge image payload)
owner GET /ds/python_cell/1/result/     → forged payload persisted
peer PUT /ds/data_cell/1/               → 401 CANNOT_WRITE_DATADOC
```

Runner: `proof_e2e.py` → **OVERALL: PASS** (5/5). Log: `evidence/e2e_run.log`.

## Suggested fix

On both Python result handlers, resolve the parent DataDoc and call:

- GET → `assert_can_read(doc_id)` (+ existing `verify_data_cell_permission` if engine checks remain desired)
- PUT → `assert_can_write(doc_id)`

Mirror `logic/datadoc_collab.update_data_cell` / comment paths that already bind to DataDoc ACL.

## Novelty gate (2026-11-02 Asia/Taipei)

- No GHSA/CVE for Querybook Python cell result ACL/IDOR (existing advisories: CVE-2024-28251 CSWSH, CVE-2024-27103/26148 stored XSS, CVE-2022-46151 reflected XSS — unrelated).
- `python_cell.py` history: only feature commit #1559; no security patch.
- No public issue/PR discussing `python_cell` result permission vs `assert_can_read`.
- Distinct from prior ledger Querybook rejects (C96 peer-review opt-in, C97 metadata-only, C98 SSTI sandbox).

## Evidence package

- `proof_e2e.py`, `evidence/e2e_run.log`, `evidence/snippets/*`
- `EVIDENCE_C131.tar.gz` + sha256

## Reminder

Do **not** submit without explicit user approval. Do not include secrets in the public/private report bundle.
