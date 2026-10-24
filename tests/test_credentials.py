import contextlib
import base64
import pathlib
import threading
import urllib.error
import urllib.parse
import urllib.request
import unittest
import test_features

class CredentialTests(unittest.TestCase):
    def setUp(self):
        test_features.FeatureTests.setUp(self)
        pathlib.Path(self.app.PASSWORD_FILE).write_text('test-only-password')
        self.server=self.app.Server(('127.0.0.1',0),self.app.Handler)
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.base='http://127.0.0.1:'+str(self.server.server_port)
        self.auth={'Authorization':'Basic '+base64.b64encode(b'frog:test-only-password').decode()}

    def submit(self,username='bot-user',password='test-password',path='/login'):
        data=urllib.parse.urlencode({'username':username,'password':password}).encode()
        with urllib.request.urlopen(urllib.request.Request(self.base+path,data=data)) as response:
            return response.status

    def test_capture_and_private_database(self):
        self.assertEqual(self.submit(),200)
        with self.app.credentials_connect() as c:
            self.assertEqual(c.execute('SELECT username,password FROM submissions').fetchall(),[('bot-user','test-password')])
        self.assertEqual(pathlib.Path(self.app.CREDENTIALS_DB).stat().st_mode&0o777,0o600)
        self.assertNotIn('test-password',pathlib.Path(self.app.EVENTFILE).read_text())
        with self.app.db_connect() as c:
            self.assertFalse(c.execute("SELECT name FROM sqlite_master WHERE name='submissions'").fetchall())

    def test_authorization_and_html_escaping(self):
        self.submit('<script>','<img onerror=1>')
        with self.assertRaises(urllib.error.HTTPError) as result:
            urllib.request.urlopen(self.base+'/credentials')
        self.assertEqual(result.exception.code,401);result.exception.close()
        with urllib.request.urlopen(urllib.request.Request(self.base+'/credentials',headers=self.auth)) as response:
            page=response.read().decode()
        self.assertIn('&lt;script&gt;',page)
        self.assertIn('&lt;img onerror=1&gt;',page)
        self.assertNotIn('<img onerror',page)

    def test_disabled_and_admin_login_not_collected(self):
        self.app.CONFIG['capture_credentials']=False
        self.submit()
        self.app.CONFIG['capture_credentials']=True
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.submit(path='/soc')
        self.assertEqual(error.exception.code,401);error.exception.close()
        with self.app.credentials_connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM submissions').fetchone()[0],0)

    def test_body_limits_and_content_type(self):
        for body,headers,expected in [(b'x'*4097,{'Content-Type':'application/x-www-form-urlencoded'},413),(b'{}',{'Content-Type':'text/plain'},415),(b'&'.join([b'x=1']*17),{'Content-Type':'application/x-www-form-urlencoded'},400)]:
            with self.subTest(expected=expected),self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(urllib.request.Request(self.base+'/login',data=body,headers=headers))
            self.assertEqual(error.exception.code,expected);error.exception.close()

    def test_retention_and_size_cap(self):
        self.app.CONFIG['retention']['credentials_rows']=2
        for value in ('one','two','three'): self.submit(password=value)
        with self.app.credentials_connect() as c:
            self.assertEqual(c.execute('SELECT password FROM submissions ORDER BY id').fetchall(),[('two',),('three',)])
            c.execute('UPDATE submissions SET ts=0')
        self.app.maintenance_once()
        with self.app.credentials_connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM submissions').fetchone()[0],0)

    def test_field_lengths_and_no_backup(self):
        self.submit('u'*300,'p'*700)
        with self.app.credentials_connect() as c:
            self.assertEqual(c.execute('SELECT length(username),length(password) FROM submissions').fetchone(),(256,512))
        self.app.maintenance_once()
        import sqlite3
        backup=next((self.root/'backups'/'automatic').glob('*.sqlite3'))
        with contextlib.closing(sqlite3.connect(backup)) as c:
            self.assertFalse(c.execute("SELECT name FROM sqlite_master WHERE name='submissions'").fetchall())

if __name__=='__main__': unittest.main()
