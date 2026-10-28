"""The writer's per-tick budget sum must not scan the whole ledger history."""
import datetime as dt
from pathlib import Path
import sqlite3
import tempfile
import unittest

from dazzle import budget, domain
from dazzle.store import SCHEMA, Store, timestamp

INDEX = "CREATE INDEX IF NOT EXISTS ledger_cycle_usage ON ledger(cycle_id,upload,download);"


class LedgerIndexTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.now = dt.datetime(2026, 11, 1, 8, 19, tzinfo=dt.timezone.utc)

    def rows(self, store, cycle_id, count, size=1000):
        store.conn.execute("INSERT OR IGNORE INTO users(id,name,role,port,created_at,updated_at) VALUES('user','User','member',24431,?,?)",
                           (timestamp(self.now), timestamp(self.now)))
        store.conn.executemany("INSERT INTO ledger VALUES (?,?,?,?,?,?,?,?)",
                               [("minute-%s-%d" % (cycle_id, index), "user", cycle_id, "epoch", size, 2 * size,
                                 timestamp(self.now), timestamp(self.now)) for index in range(count)])

    def budget_query(self, store):
        """The exact statement budget._used_this_cycle runs on every tick."""
        statements = []
        store.conn.set_trace_callback(statements.append)
        try:
            used = budget._used_this_cycle(store)
        finally:
            store.conn.set_trace_callback(None)
        return used, next(sql for sql in statements if "FROM ledger" in sql)

    def test_current_cycle_sum_uses_the_covering_index_not_a_history_scan(self):
        with Store(self.folder.name, now=self.now) as store:
            current = domain.ensure_cycle(store, self.now)["id"]
            self.rows(store, "quota-older", 50)
            self.rows(store, current, 3)
            used, sql = self.budget_query(store)
            self.assertEqual(used, 3 * 3000)
            plan = " ".join(row[-1] for row in store.conn.execute("EXPLAIN QUERY PLAN " + sql))
            self.assertIn("COVERING INDEX ledger_cycle_usage", plan)
            self.assertNotIn("SCAN ledger", plan)

    def test_existing_database_gains_the_index_without_changing_rows(self):
        path = Path(self.folder.name) / "state.sqlite3"
        old = sqlite3.connect(path)
        self.assertIn(INDEX, SCHEMA)
        old.executescript(SCHEMA.replace(INDEX, ""))
        old.executemany("INSERT INTO ledger VALUES (?,?,?,?,?,?,?,?)",
                        [("row-%d" % index, "user", "quota-x", "epoch", index, index, "t", "t") for index in range(20)])
        old.commit()
        self.assertIsNone(old.execute("SELECT 1 FROM sqlite_master WHERE name='ledger_cycle_usage'").fetchone())
        before = old.execute("SELECT * FROM ledger ORDER BY id").fetchall()
        old.close()
        with Store(self.folder.name, now=self.now) as store:
            self.assertTrue(store.conn.execute("SELECT 1 FROM sqlite_master WHERE type='index' AND name='ledger_cycle_usage'").fetchone())
            self.assertEqual([tuple(row) for row in store.conn.execute("SELECT * FROM ledger ORDER BY id")], before)


if __name__ == "__main__":
    unittest.main()
