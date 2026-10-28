"""Rehearsal stand-in used only by the coordinator's additive-migration check on a private copy."""
from pathlib import Path
import sqlite3


class ProductionStore:
    def __init__(self, folder, *, policy, **_):
        self.policy = policy
        self.conn = sqlite3.connect(Path(folder) / "state.sqlite3")

    def close(self):
        self.conn.close()
