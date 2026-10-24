import contextlib
import importlib.util
import pathlib
import sqlite3
import tempfile
import types
import unittest

spec=importlib.util.spec_from_file_location('verify',pathlib.Path(__file__).resolve().parents[1]/'tools/verify_ssh_capture.py')
verify=importlib.util.module_from_spec(spec);spec.loader.exec_module(verify)

class CleanupTests(unittest.TestCase):
    def test_cleanup_preserves_other_credentials_and_marks_inflight_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool=pathlib.Path(tmp)/'spool.sqlite3';db=pathlib.Path(tmp)/'dashboard.sqlite3'
            with contextlib.closing(sqlite3.connect(spool)) as c, c:
                c.execute('CREATE TABLE attempts (id TEXT PRIMARY KEY,username TEXT,password TEXT)')
                c.executemany('INSERT INTO attempts VALUES (?,?,?)',[('test-id','synthetic-test','synthetic-password'),('keep-id','synthetic-other','other-password')])
            with contextlib.closing(sqlite3.connect(db)) as c, c:
                c.execute('CREATE TABLE submissions (username TEXT,password TEXT,profile TEXT)')
                c.execute('CREATE TABLE imported_sources (id TEXT PRIMARY KEY,ts REAL)')
                c.executemany('INSERT INTO submissions VALUES (?,?,?)',[('synthetic-test','synthetic-password','ssh'),('synthetic-other','other-password','ssh')])
            @contextlib.contextmanager
            def connect():
                with contextlib.closing(sqlite3.connect(db)) as c, c: yield c
            app=types.SimpleNamespace(credentials_connect=connect)
            ids=verify.cleanup_spool(spool,'synthetic-test','synthetic-password')
            self.assertEqual(ids,['test-id'])
            verify.cleanup_credentials(app,'synthetic-test','synthetic-password',ids)
            with connect() as c:
                self.assertEqual(c.execute('SELECT username FROM submissions').fetchall(),[('synthetic-other',)])
                self.assertEqual(c.execute('SELECT id FROM imported_sources').fetchall(),[('test-id',)])
            with contextlib.closing(sqlite3.connect(spool)) as c:
                self.assertEqual(c.execute('SELECT id FROM attempts').fetchall(),[('keep-id',)])
            self.assertEqual(verify.cleanup_spool(spool,'synthetic-test','synthetic-password'),[])
            verify.cleanup_credentials(app,'synthetic-test','synthetic-password',ids)
