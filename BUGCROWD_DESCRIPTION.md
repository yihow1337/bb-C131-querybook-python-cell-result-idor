## Title
Querybook: /ds/python_cell/<id>/result/ skips DataDoc ACL (env-peer IDOR read+write)

## Target
github.com/pinterest/querybook @ ebd3e63a (OSS in Pinterest Bugcrowd scope)

## Severity
High — CWE-639/863. Same-environment peer without DataDoc editor/read can GET and PUT private Python cell results while sibling /ds/datadoc and /ds/data_cell correctly deny.

## Steps
1. Env with users A (owner) and B (peer, no DataDoc ACL).
2. A creates private DataDoc + Python cell; stores result with sensitive JSON.
3. As B: GET /ds/datadoc/<id>/ → 403 CANNOT_READ_DATADOC.
4. As B: GET /ds/python_cell/<cell_id>/result/ → 200 with secret output.
5. As B: PUT /ds/python_cell/<cell_id>/result/ with forged image/json → 200; A sees forged output.
6. As B: PUT /ds/data_cell/<cell_id>/ → 401 CANNOT_WRITE_DATADOC (sibling control).

## Root cause
python_cell.py only calls verify_data_cell_permission (environment membership). Missing assert_can_read/assert_can_write used by datadoc siblings.

## Fix
Gate GET with assert_can_read and PUT with assert_can_write on the parent DataDoc.

## Proof
Local Flask test-client e2e OVERALL PASS (attached). No production Pinterest SaaS testing performed.
