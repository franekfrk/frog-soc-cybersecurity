import contextlib,pathlib
import json,sqlite3,time,urllib.request,urllib.error
import test_credentials
import unittest

class ProtocolTests(unittest.TestCase):
    def setUp(self): test_credentials.CredentialTests.setUp(self)
    def post(self,path,body,kind):
        try:
            r=urllib.request.urlopen(urllib.request.Request(self.base+path,data=body,headers={'Content-Type':kind}))
        except urllib.error.HTTPError as e: r=e
        with r:return r.code,r.headers,r.read().decode()
    def test_json_vendor_and_xmlrpc(self):
        code,headers,body=self.post('/RPC2',json.dumps({'params':{'userName':'cam-test','password':'cam-secret'}}).encode(),'application/json')
        self.assertEqual(code,401);self.assertNotIn('cam-secret',body);self.assertIn('HttpOnly',headers['Set-Cookie'])
        xml=b'<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>wp-test</string></value></param><param><value><string>wp-secret</string></value></param></params></methodCall>'
        code,headers,body=self.post('/xmlrpc.php',xml,'text/xml')
        self.assertEqual(code,200);self.assertIn('<fault>',body)
        with self.app.credentials_connect() as c:
            self.assertEqual(c.execute('SELECT username,password,profile FROM submissions ORDER BY id').fetchall(),[('cam-test','cam-secret','camera'),('wp-test','wp-secret','wordpress')])
        self.assertNotIn('secret',pathlib.Path(self.app.EVENTFILE).read_text())
    def test_reject_invalid_and_entity_xml(self):
        for raw,kind in [(b'<bad','text/xml'),('<!DOCTYPE x [<!ENTITY x "no">]><x>&x;</x>'.encode('utf-16'),'text/xml'),(b'<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><x>&x;</x>','text/xml'),(b'[]','application/json'),(b'{"params":{"a":{}}}','application/json')]:
            self.assertEqual(self.post('/api/login',raw,kind)[0],400)
        with self.app.credentials_connect() as c:self.assertEqual(c.execute('SELECT COUNT(*) FROM submissions').fetchone()[0],0)
    def test_redirect_and_local_asset(self):
        with urllib.request.urlopen(self.base+'/wp-admin') as r:
            self.assertTrue(r.url.endswith('/wp-login.php'));self.assertIn('wordpress_test_cookie',r.headers['Set-Cookie'])
        with urllib.request.urlopen(self.base+'/wp-includes/css/buttons.min.css') as r:self.assertEqual(r.headers.get_content_type(),'text/css')
    def test_ssh_spool_import_is_idempotent(self):
        a=self.app;path=self.root/'spool.db';a.CONFIG['ssh_capture'].update(enabled=True,spool=str(path))
        with contextlib.closing(sqlite3.connect(path)) as c, c:
            c.execute('CREATE TABLE attempts (id TEXT PRIMARY KEY,ts REAL,ip TEXT,username TEXT,password TEXT)')
            c.execute('INSERT INTO attempts VALUES (?,?,?,?,?)',('id',time.time(),'8.8.8.8','ssh-test','ssh-secret'))
        a.ssh_capture_import()
        with contextlib.closing(sqlite3.connect(path)) as c, c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM attempts').fetchone()[0],1)
            c.execute('UPDATE attempts SET ts=ts WHERE id=?',('id',))
        a.ssh_capture_import()
        with a.credentials_connect() as c:self.assertEqual(c.execute('SELECT COUNT(*) FROM submissions').fetchone()[0],1)
        self.assertTrue(any(key=='trap:ssh' for key,_ in a.trap_alerts()))

    def test_deleted_ssh_attempt_is_not_reimported(self):
        a=self.app;path=self.root/'spool-delete.db';a.CONFIG['ssh_capture'].update(enabled=True,spool=str(path))
        with contextlib.closing(sqlite3.connect(path)) as c, c:
            c.execute('CREATE TABLE attempts (id TEXT PRIMARY KEY,ts REAL,ip TEXT,username TEXT,password TEXT)')
            c.execute('INSERT INTO attempts VALUES (?,?,?,?,?)',('del-id',time.time(),'8.8.8.8','u','p'))
        a.ssh_capture_import()
        with a.credentials_connect() as c:c.execute('DELETE FROM submissions')
        a.ssh_capture_import()
        with a.credentials_connect() as c:self.assertEqual(c.execute('SELECT COUNT(*) FROM submissions').fetchone()[0],0)
