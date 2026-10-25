"""SQLite descriptors and WAL locks: temporary state only, never production data."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from dazzle.store import Store


class StoreWALTests(unittest.TestCase):
    def test_existing_database_never_gets_a_raw_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Store(directory)
            try:
                first.set_meta("first_connection", 17)
                raw_open = os.open
                def no_existing_db_open(path, flags, *args, **kwargs):
                    if Path(path) == first.path:
                        raise AssertionError("Existing SQLite DB was directly opened outside SQLite")
                    return raw_open(path, flags, *args, **kwargs)
                with patch("dazzle.store.os.open", side_effect=no_existing_db_open):
                    with Store(directory) as second:
                        self.assertEqual(second.get_meta("first_connection"), 17)
                        second.set_meta("second_connection", 23)
                        self.assertEqual(first.get_meta("second_connection"), 23)
                        self.assertEqual(second.conn.execute("PRAGMA quick_check").fetchone()[0], "ok")
                self.assertTrue(Path(str(first.path) + "-wal").is_file())
                self.assertEqual(first.get_meta("second_connection"), 23)
                self.assertEqual(first.path.stat().st_mode & 0o777, 0o600)
            finally:
                first.close()

    def test_new_database_creation_is_exclusive_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_open, calls = os.open, []
            database = Path(directory) / "state.sqlite3"
            def observe(path, flags, *args, **kwargs):
                if Path(path) == database:
                    calls.append(flags)
                return raw_open(path, flags, *args, **kwargs)
            with patch("dazzle.store.os.open", side_effect=observe):
                with Store(directory) as store:
                    self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(calls), 1)
            self.assertTrue(calls[0] & os.O_CREAT)
            self.assertTrue(calls[0] & os.O_EXCL)
            self.assertTrue(calls[0] & os.O_NOFOLLOW)

    def test_symlink_database_and_symlink_directory_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "private-target"
            target.write_text("unchanged fixture")
            target.chmod(0o640)
            state = base / "state"
            state.mkdir()
            (state / "state.sqlite3").symlink_to(target)
            with self.assertRaises(ValueError):
                Store(state)
            self.assertEqual(target.read_text(), "unchanged fixture")
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)
            alias = base / "alias"
            alias.symlink_to(state, target_is_directory=True)
            with self.assertRaises(ValueError):
                Store(alias)

    def test_concurrent_creator_eexist_does_not_reopen_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            raw_open, created = os.open, []
            def competing_creator(path, flags, *args, **kwargs):
                if Path(path) == database and not created:
                    descriptor = raw_open(path, flags, *args, **kwargs)
                    os.close(descriptor)
                    created.append(True)
                    raise FileExistsError("Fixture other process won exclusive creation")
                if Path(path) == database:
                    raise AssertionError("Concurrent winner database was reopened raw")
                return raw_open(path, flags, *args, **kwargs)
            with patch("dazzle.store.os.open", side_effect=competing_creator):
                with Store(directory) as store:
                    self.assertEqual(store.conn.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertEqual(len(created), 1)

    def test_threaded_openers_use_sqlite_connections_without_raw_existing_db_open(self):
        with tempfile.TemporaryDirectory() as directory:
            with Store(directory) as observer:
                barrier = threading.Barrier(2)
                errors = []
                raw_open = os.open
                def reject_raw_existing(path, flags, *args, **kwargs):
                    if Path(path) == observer.path:
                        raise AssertionError("Threaded opener opened the existing database raw")
                    return raw_open(path, flags, *args, **kwargs)
                def worker(index):
                    try:
                        with Store(directory) as connection:
                            connection.set_meta("thread_" + str(index), index)
                            barrier.wait(timeout=5)
                            self.assertEqual(connection.get_meta("thread_0"), 0)
                            self.assertEqual(connection.get_meta("thread_1"), 1)
                            self.assertEqual(connection.conn.execute("PRAGMA quick_check").fetchone()[0], "ok")
                    except BaseException as exc:
                        errors.append(exc)
                        barrier.abort()
                with patch("dazzle.store.os.open", side_effect=reject_raw_existing):
                    threads = [threading.Thread(target=worker, args=(index,)) for index in (0, 1)]
                    for thread in threads:
                        thread.start()
                    for thread in threads:
                        thread.join(timeout=7)
                self.assertFalse(any(thread.is_alive() for thread in threads))
                self.assertEqual(errors, [])
                self.assertEqual(observer.get_meta("thread_0"), 0)
                self.assertEqual(observer.get_meta("thread_1"), 1)

    @unittest.skipUnless(sys.platform.startswith("linux"), "POSIX SQLite lock and deleted-WAL regression requires Linux")
    def test_linux_multiple_connections_keep_locks_and_wal_across_external_open_close(self):
        script = r'''
import fcntl,json,os,pathlib,subprocess,sys,tempfile
from dazzle.store import Store
probe = """import fcntl,os,sys
fd=os.open(sys.argv[1],os.O_RDWR)
try:
 fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB,1,0x40000002,os.SEEK_SET)
except BlockingIOError:
 print('locked')
else:
 print('unlocked')
finally:
 os.close(fd)
"""
with tempfile.TemporaryDirectory() as directory:
 with Store(directory) as first:
  first.set_meta('fixture_first',1)
  before=subprocess.check_output([sys.executable,'-c',probe,str(first.path)],text=True).strip()
  assert before=='locked',before
  with Store(directory) as second:
   after=subprocess.check_output([sys.executable,'-c',probe,str(first.path)],text=True).strip()
   assert after=='locked',after
   for value in range(4):
    second.set_meta('fixture_second',value)
    external="from dazzle.store import Store;import sys\nwith Store(sys.argv[1]) as s:s.set_meta('fixture_external',7)"
    subprocess.check_call([sys.executable,'-c',external,directory])
    assert first.get_meta('fixture_external')==7
    assert first.get_meta('fixture_second')==value
    assert second.conn.execute('PRAGMA quick_check').fetchone()[0]=='ok'
    assert pathlib.Path(str(first.path)+'-wal').exists()
    deleted=[os.readlink('/proc/self/fd/'+name) for name in os.listdir('/proc/self/fd') if os.path.exists('/proc/self/fd/'+name)]
    assert not any(('state.sqlite3-wal' in name or 'state.sqlite3-shm' in name) and name.endswith(' (deleted)') for name in deleted)
 print(json.dumps({'locks':'preserved','wal':'attached','integrity':'ok'}))
'''
        result = subprocess.run([sys.executable, "-c", script], text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        self.assertEqual(json.loads(result.stdout), {"locks": "preserved", "wal": "attached", "integrity": "ok"})


if __name__ == "__main__":
    unittest.main()
