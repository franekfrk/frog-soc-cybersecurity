import json
import pathlib
import urllib.request
import urllib.error
import test_credentials
import unittest

class NewTrapTests(unittest.TestCase):
    def setUp(self): test_credentials.CredentialTests.setUp(self)

    def get(self,path):
        with urllib.request.urlopen(self.base+path) as r: return r.headers,r.read().decode()

    def test_docker_json_versions_and_denied_mutations(self):
        for prefix in ('','/v1.43'):
            for path in ('/version','/info','/containers/json','/images/json'):
                headers,body=self.get(prefix+path)
                self.assertEqual(headers.get_content_type(),'application/json')
                self.assertIsInstance(json.loads(body),(dict,list))
            self.assertEqual(self.get(prefix+'/_ping')[1],'OK')
        request=urllib.request.Request(self.base+'/v1.43/containers/create',data=b'{"Cmd":["should-never-execute-XYZ"]}',headers={'Content-Type':'application/json'})
        with self.assertRaises(urllib.error.HTTPError) as error: urllib.request.urlopen(request)
        self.assertEqual(error.exception.code,403);error.exception.close()
        for method in ('DELETE','PUT','PATCH'):
            request=urllib.request.Request(self.base+'/v1.43/containers/web',method=method)
            with self.assertRaises(urllib.error.HTTPError) as error: urllib.request.urlopen(request)
            self.assertEqual(error.exception.code,403);error.exception.close()
        self.assertNotIn('should-never-execute-XYZ',pathlib.Path(self.app.EVENTFILE).read_text())
        self.assertFalse(any(key=='trap:Docker API' for key,_ in self.app.trap_alerts()))
        self.app.log_event('8.8.8.8', '/version', 'GET')
        self.assertTrue(any(key=='trap:Docker API' for key,_ in self.app.trap_alerts()))
        self.app.CONFIG['honeypots']['docker_api']=False
        with self.assertRaises(urllib.error.HTTPError) as error: self.get('/version')
        self.assertEqual(error.exception.code,404);error.exception.close()

    def test_config_lures_and_classification(self):
        for path in self.app.EXTRA_DECOYS:
            _,body=self.get(path)
            self.assertEqual(body,self.app.EXTRA_DECOYS[path])
            self.assertEqual(self.app.scan_classification(path)[0],'Pliki konfiguracyjne')
        self.assertEqual(self.app.scan_classification('/.git/config')[0],'Repozytorium Git')
        self.assertEqual(self.app.scan_classification('/phpmyadmin/index.php')[0],'phpMyAdmin')
        self.assertFalse(any(key=='trap:Pliki konfiguracyjne' for key,_ in self.app.trap_alerts()))
        self.app.log_event('8.8.8.8', '/.env.production', 'GET')
        self.assertTrue(any(key=='trap:Pliki konfiguracyjne' for key,_ in self.app.trap_alerts()))

    def test_phpmyadmin_capture_and_disable(self):
        import urllib.parse
        data=urllib.parse.urlencode({'pma_username':'synthetic-db-user','pma_password':'synthetic-db-password'}).encode()
        with urllib.request.urlopen(self.base+'/phpmyadmin/index.php',data=data) as r: self.assertIn('Sign-in failed',r.read().decode())
        with self.app.credentials_connect() as c:
            self.assertEqual(c.execute('SELECT username,password,profile FROM submissions').fetchone(),('synthetic-db-user','synthetic-db-password','phpmyadmin'))
        self.assertFalse(any(key=='trap:phpMyAdmin' for key,_ in self.app.trap_alerts()))
        self.app.log_event('8.8.8.8', '/phpmyadmin', 'GET')
        self.assertTrue(any(key=='trap:phpMyAdmin' for key,_ in self.app.trap_alerts()))
        self.app.CONFIG['honeypots']['enabled'].remove('phpmyadmin')
        with self.assertRaises(urllib.error.HTTPError) as error: self.get('/phpmyadmin')
        self.assertEqual(error.exception.code,404);error.exception.close()
