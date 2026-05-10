import gc
import os
import sqlite3
import tempfile
import time
from unittest.mock import patch

from flask import Flask

import beacon_x402
import rustchain_x402


def _make_rustchain_x402_app(db_path):
    app = Flask(__name__)
    app.config["TESTING"] = True
    rustchain_x402.init_app(app, db_path)
    return app


def _make_balances_db():
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp.close()
    with sqlite3.connect(tmp.name) as conn:
        conn.execute(
            """
            CREATE TABLE balances (
                miner_id TEXT PRIMARY KEY,
                miner_pk TEXT,
                balance INTEGER DEFAULT 0
            )
            """
        )
    return tmp.name


def _make_beacon_db():
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp.close()
    conn = sqlite3.connect(tmp.name)
    return tmp.name, conn


def _unlink_temp_db(db_path):
    for _ in range(5):
        try:
            os.unlink(db_path)
            return
        except PermissionError:
            gc.collect()
            time.sleep(0.05)


def test_rustchain_x402_link_coinbase_uses_constant_time_admin_key_compare(monkeypatch):
    db_path = _make_balances_db()
    monkeypatch.setenv("RC_ADMIN_KEY", "expected-admin-key")

    try:
        app = _make_rustchain_x402_app(db_path)
        client = app.test_client()

        with patch("hmac.compare_digest", return_value=False) as compare_digest:
            response = client.post(
                "/wallet/link-coinbase",
                headers={"X-Admin-Key": "wrong-admin-key"},
                json={
                    "miner_id": "alice",
                    "coinbase_address": "0x0000000000000000000000000000000000000001",
                },
            )

        assert response.status_code == 401
        compare_digest.assert_called_once_with("wrong-admin-key", "expected-admin-key")
    finally:
        _unlink_temp_db(db_path)


def test_rustchain_x402_link_coinbase_accepts_valid_admin_key(monkeypatch):
    db_path = _make_balances_db()
    monkeypatch.setenv("RC_ADMIN_KEY", "expected-admin-key")

    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "INSERT INTO balances (miner_id, miner_pk, balance) VALUES (?, ?, ?)",
                ("alice", "alice-pk", 0),
            )

        app = _make_rustchain_x402_app(db_path)
        client = app.test_client()

        with patch("hmac.compare_digest", wraps=rustchain_x402.hmac.compare_digest) as compare_digest:
            response = client.post(
                "/wallet/link-coinbase",
                headers={"X-Admin-Key": "expected-admin-key"},
                json={
                    "miner_id": "alice",
                    "coinbase_address": "0x0000000000000000000000000000000000000001",
                },
            )

        assert response.status_code == 200
        assert response.get_json()["ok"] is True
        compare_digest.assert_called_once_with("expected-admin-key", "expected-admin-key")

        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT coinbase_address FROM balances WHERE miner_id = ?",
                ("alice",),
            ).fetchone()
        assert row == ("0x0000000000000000000000000000000000000001",)
    finally:
        _unlink_temp_db(db_path)


def test_beacon_x402_agent_wallet_uses_constant_time_admin_key_compare(monkeypatch):
    app = Flask(__name__)
    app.config["TESTING"] = True
    monkeypatch.setenv("BEACON_ADMIN_KEY", "expected-beacon-admin-key")

    with patch.object(beacon_x402, "_run_migrations"):
        beacon_x402.init_app(app, lambda: None)

    client = app.test_client()
    with patch("hmac.compare_digest", return_value=False) as compare_digest:
        response = client.post(
            "/api/agents/agent-1/wallet",
            headers={"X-Admin-Key": "wrong-beacon-admin-key"},
            json={"coinbase_address": "0x0000000000000000000000000000000000000001"},
        )

    assert response.status_code == 401
    compare_digest.assert_called_once_with(
        "wrong-beacon-admin-key",
        "expected-beacon-admin-key",
    )


def test_beacon_x402_agent_wallet_accepts_valid_admin_key(monkeypatch):
    app = Flask(__name__)
    app.config["TESTING"] = True
    monkeypatch.setenv("BEACON_ADMIN_KEY", "expected-beacon-admin-key")
    db_path, db = _make_beacon_db()

    try:
        db.executescript(beacon_x402.X402_BEACON_SCHEMA)
        db.commit()

        with patch.object(beacon_x402, "_run_migrations"):
            beacon_x402.init_app(app, lambda: db)

        client = app.test_client()
        with patch("hmac.compare_digest", wraps=beacon_x402.hmac.compare_digest) as compare_digest:
            response = client.post(
                "/api/agents/agent-1/wallet",
                headers={"X-Admin-Key": "expected-beacon-admin-key"},
                json={"coinbase_address": "0x0000000000000000000000000000000000000001"},
            )

        assert response.status_code == 200
        assert response.get_json()["ok"] is True
        compare_digest.assert_called_once_with(
            "expected-beacon-admin-key",
            "expected-beacon-admin-key",
        )

        row = db.execute(
            "SELECT coinbase_address FROM beacon_wallets WHERE agent_id = ?",
            ("agent-1",),
        ).fetchone()
        assert row == ("0x0000000000000000000000000000000000000001",)
    finally:
        db.close()
        _unlink_temp_db(db_path)
