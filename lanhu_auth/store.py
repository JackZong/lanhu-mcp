"""Encrypted, persistent OAuth records. Raw bearer tokens are never database keys."""

import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.fernet import Fernet


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class Store:
    def __init__(self, root: Path, key: str):
        root.mkdir(parents=True, exist_ok=True)
        self.cipher = Fernet(key.encode())
        self.path = root / "oauth.sqlite3"
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, value BLOB, expires REAL, PRIMARY KEY(kind,id))"
            )
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=15)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def put(self, kind, key, value, ttl=86400):
        encrypted = self.cipher.encrypt(json.dumps(value).encode())
        with self.connect() as db:
            db.execute("DELETE FROM records WHERE expires < ?", (time.time(),))
            db.execute(
                "INSERT OR REPLACE INTO records VALUES (?,?,?,?)", (kind, digest(key), encrypted, time.time() + ttl)
            )

    def get(self, kind, key, consume=False):
        with self.connect() as db:
            if consume:
                db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT value, expires FROM records WHERE kind=? AND id=?", (kind, digest(key))).fetchone()
            if consume:
                db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, digest(key)))
        if not row or row[1] <= time.time():
            return None
        return json.loads(self.cipher.decrypt(row[0]))

    def delete(self, kind, key):
        with self.connect() as db:
            db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, digest(key)))
