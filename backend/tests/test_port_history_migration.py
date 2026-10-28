"""History migration preserves existing schema definitions and all user data."""
import collections
from pathlib import Path
import sqlite3
import tempfile
import unittest

from dazzle.store import SCHEMA, Store


class PortHistoryMigrationTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "state.sqlite3"
        connection = sqlite3.connect(self.path)
        connection.executescript(SCHEMA.replace("port INTEGER NOT NULL,", "port INTEGER NOT NULL UNIQUE,", 1))
        connection.executescript("""
CREATE INDEX "Names With Spaces" ON users(name COLLATE NOCASE);
CREATE UNIQUE INDEX unique_existing_email ON users(email) WHERE email IS NOT NULL;
CREATE TABLE migration_audit (user_id TEXT, name TEXT);
CREATE TABLE user_child (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE);
CREATE TRIGGER preserve_user_audit AFTER UPDATE OF name ON users
BEGIN
 INSERT INTO migration_audit(user_id,name) VALUES(new.id,new.name);
END;
CREATE VIEW preserved_user_view AS SELECT id,name FROM users;
""")
        at = "2026-10-26T00:00:00.000000Z"
        connection.execute("INSERT INTO users(id,name,role,port,quota_bytes,used_upload,used_download,created_at,updated_at,revoked_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                           ("archived-member", "Archived", "member", 24431, 100_000_000_000, 111, 222, at, at, at))
        connection.execute("INSERT INTO users(id,name,role,port,unlimited,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                           ("administrator", "Administrator", "admin", 24430, 1, at, at))
        connection.execute("INSERT INTO user_child VALUES('child','archived-member')")
        connection.commit()
        self.columns = {table: [row[1] for row in connection.execute('PRAGMA table_info("' + table + '")')]
                        for (table,) in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        self.before = self.facts(connection, self.columns)
        self.objects = list(connection.execute("SELECT type,name,sql FROM sqlite_master WHERE type IN ('index','trigger','view') AND sql IS NOT NULL ORDER BY type,name"))
        connection.close()

    def facts(self, connection, columns=None):
        # Every original column must survive verbatim; later additive columns may follow.
        if columns is None:
            columns = {table: [row[1] for row in connection.execute('PRAGMA table_info("' + table + '")')]
                       for (table,) in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        return {table: collections.Counter(tuple(row) for row in connection.execute(
                    "SELECT " + ",".join('"' + name + '"' for name in names) + ' FROM "' + table + '"'))
                for table, names in columns.items()}

    def test_existing_indexes_triggers_views_and_child_rows_survive_verbatim(self):
        with Store(self.folder.name) as store:
            after = self.facts(store.conn, self.columns)
            for table, rows in self.before.items():
                with self.subTest(table=table):
                    self.assertLessEqual(rows, after[table])
            for kind, name, sql in self.objects:
                with self.subTest(object=name):
                    self.assertEqual(store.conn.execute("SELECT sql FROM sqlite_master WHERE type=? AND name=?", (kind, name)).fetchone()[0], sql)
            self.assertEqual(store.conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(store.conn.execute("PRAGMA legacy_alter_table").fetchone()[0], 0)
            self.assertEqual(list(store.conn.execute("PRAGMA foreign_key_check")), [])
            self.assertEqual(store.conn.execute("SELECT COUNT(*) FROM migration_audit").fetchone()[0], 0)
            self.assertEqual(store.conn.execute("SELECT COUNT(*) FROM preserved_user_view").fetchone()[0], 2)
            store.conn.execute("UPDATE users SET name='Still audited' WHERE id='archived-member'")
            self.assertEqual(tuple(store.conn.execute("SELECT * FROM migration_audit").fetchone()), ("archived-member", "Still audited"))

    def test_only_archived_ports_become_reusable_and_other_constraints_remain(self):
        with Store(self.folder.name) as store:
            at = "2026-10-26T00:00:00.000000Z"
            sql = "INSERT INTO users(id,name,role,port,email,created_at,updated_at) VALUES(?,?,?,?,?,?,?)"
            store.conn.execute(sql, ("new-member", "New member", "member", 24431, "unique@example.test", at, at))
            with self.assertRaises(sqlite3.IntegrityError):
                store.conn.execute(sql, ("duplicate-port", "Duplicate port", "member", 24431, None, at, at))
            with self.assertRaises(sqlite3.IntegrityError):
                store.conn.execute(sql, ("duplicate-email", "Duplicate email", "member", 24432, "unique@example.test", at, at))
            with self.assertRaises(sqlite3.IntegrityError):
                store.conn.execute(sql, ("duplicate-admin", "Duplicate admin", "admin", 24432, None, at, at))
            with self.assertRaises(sqlite3.IntegrityError):
                store.conn.execute("INSERT INTO user_child VALUES('unknown-child','missing-user')")
            self.assertEqual(store.conn.execute("SELECT used_upload+used_download FROM users WHERE id='archived-member'").fetchone()[0], 333)

    def test_failed_recreation_rolls_back_table_rows_and_restores_pragmas(self):
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA legacy_alter_table=OFF")
        before = self.facts(connection)
        objects = list(connection.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name"))
        def authorizer(action, first, _second, _database, _source):
            if action == sqlite3.SQLITE_CREATE_TRIGGER and first == "preserve_user_audit":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        connection.set_authorizer(authorizer)
        fake = Store.__new__(Store)
        fake.conn = connection
        with self.assertRaises(sqlite3.DatabaseError):
            fake._migrate_port_history()
        connection.set_authorizer(None)
        self.assertEqual(self.facts(connection), before)
        self.assertEqual(list(connection.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name")), objects)
        self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(connection.execute("PRAGMA legacy_alter_table").fetchone()[0], 0)
        connection.close()
