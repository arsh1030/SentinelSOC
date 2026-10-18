"""
Point the store at a throwaway FalkorDB before any test touches it.

Without this the suite would write test sessions into data/sentinel.falkordb, or
into whatever server FALKORDB_URL names.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import pytest  # noqa: E402

import store  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _isolated_graph(tmp_path_factory):
    if not os.getenv("FALKORDB_URL"):
        store.DB_PATH = tmp_path_factory.mktemp("falkordb") / "test.falkordb"
    store.GRAPH_NAME = f"sentinel_test_{os.getpid()}"
    store._db = None
    store._initialised.clear()
    yield
    try:
        store.connect().delete()
    except Exception:
        pass
    client, store._db = store._db, None
    if client is not None and hasattr(client, "close"):
        client.close()
