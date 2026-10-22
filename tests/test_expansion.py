import collections
import datetime
import json
import pathlib
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import unittest
import xml.etree.ElementTree as ET
import test_credentials

class ExpansionTests(unittest.TestCase):
    def setUp(self):
        test_credentials.CredentialTests.setUp(self)

    def get(self,path,auth=False):
        with urllib.request.urlopen(urllib.request.Request(self.base+path,headers=self.auth if auth else {})) as response:
            return response.read().decode()

    def post_rule(self,fields):
        data=urllib.parse.urlencode(fields,doseq=True).encode()
        with urllib.request.urlopen(urllib.request.Request(self.base+'/rules/save',data=data,headers=self.auth)) as response:
            return response.read().decode()

    def test_hub_six_profiles_and_capture_origin(self):
        hub=self.get('/')
        for profile in self.app.CONFIG['honeypots']['enabled']:
            self.assertIn(self.app.TRAP_PATHS[profile],hub)
            page=self.get(self.app.TRAP_PATHS[profile])
            self.assertIn('action="'+self.app.TRAP_LOGIN_PATHS[profile]+'"',page)
            data=urllib.parse.urlencode({'username':'synthetic','password':'example'}).encode()
            with urllib.request.urlopen(urllib.request.Request(self.base+self.app.TRAP_LOGIN_PATHS[profile],data=data)) as response:
                self.assertIn('Sign-in failed',response.read().decode())
        with self.app.credentials_connect() as c:
            self.assertEqual({row[0] for row in c.execute('SELECT DISTINCT profile FROM submissions')},set(self.app.TRAP_PROFILES))

    def test_legacy_submission_migration_preserves_data(self):
        import sqlite3, contextlib
        old=self.root/'legacy-credentials.sqlite3'
        with contextlib.closing(sqlite3.connect(old)) as c:
            c.execute('CREATE TABLE submissions (id INTEGER PRIMARY KEY,ts REAL,ip TEXT,username TEXT,password TEXT)')
            c.execute('INSERT INTO submissions VALUES (?,?,?,?,?)',(9,time.time(),'192.0.2.1','legacy-user','synthetic-password'))
            c.commit()
        self.app.CREDENTIALS_DB=str(old)
        with self.app.credentials_connect() as c:
            self.assertEqual(c.execute('SELECT id,username,password,profile FROM submissions').fetchone(),(9,'legacy-user','synthetic-password','router'))

    def test_public_ssh_card_is_neutral_and_configurable(self):
        hub=self.get('/')
        self.assertIn('SSH Access',hub)
        self.assertIn('ssh -p '+str(self.app.ENDLESSH_PORT)+' 127.0.0.1',hub)
        self.assertEqual(self.app.public_host('evil;command'),'SERVER_ADDRESS')
        self.assertEqual(self.app.public_host('example.org:31888'),'example.org')
        for marker in ('Endlessh','honeypot','pułapka','Frog SOC','/soc','/traps'):
            self.assertNotIn(marker,hub)
        self.app.CONFIG['honeypots']['ssh_public_port']=22222
        self.assertIn('ssh -p 22222',self.get('/'))

    def test_disabled_profile_and_single_homepage(self):
        self.app.CONFIG['honeypots']['enabled']=['nas']
        self.app.CONFIG['honeypots']['homepage']='nas'
        self.assertIn('Storage Station',self.get('/'))
        with self.assertRaises(urllib.error.HTTPError) as error:self.get('/traps/camera')
        self.assertEqual(error.exception.code,404);error.exception.close()
        self.assertNotIn('camera',self.app.trap_hub())

    def test_decoy_files_never_read_real_files(self):
        for path in ('/.env','/.git/config','/backup.zip','/config.json'):
            body=self.get(path)
            self.assertNotIn('test-only-password',body)
            self.assertTrue('DECOY' in body or 'example.invalid' in body or 'placeholder' in body)

    def test_bot_profile_ua_evidence_and_visits(self):
        self.app.log_event('192.0.2.1','/.env','GET','<DemoBot>\nsecret','router')
        self.app.log_event('192.0.2.1','/wp-login.php','GET','DemoBot/1.0','wordpress')
        body=self.app.ip_page('192.0.2.1')
        self.assertIn('Profil bota',body)
        self.assertIn('WordPress',body)
        self.assertIn('/wp-login.php',body)
        self.assertIn('&lt;DemoBot&gt;secret',body)
        self.assertNotIn('<DemoBot>',body)
        with self.app.db_connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM http_details').fetchone()[0],2)

    def test_scan_labels_and_reasons(self):
        for path,label in [('/.env','Pliki konfiguracyjne'),('/.git/config','Repozytorium Git'),('/backup.zip','Kopie zapasowe'),('/wp-admin','WordPress'),('/traps/camera','Kamera IP'),('/traps/nas','NAS'),('/traps/api','API')]:
            self.assertEqual(self.app.scan_classification(path)[0],label)
            self.assertTrue(self.app.scan_classification(path)[1])

    def test_demo_no_database_no_side_effects(self):
        original=self.app.db_connect
        original_credentials=self.app.credentials_connect
        self.app.credentials_connect=lambda: (_ for _ in ()).throw(AssertionError('Private DB access'))
        self.app.db_connect=lambda: (_ for _ in ()).throw(AssertionError('Live DB access'))
        try:
            page=self.get('/demo')
            data=json.loads(self.get('/demo/data'))
        finally:
            self.app.db_connect=original
            self.app.credentials_connect=original_credentials
        self.assertIn('WYŁĄCZNIE FIKCYJNE',page)
        self.assertNotIn('/assets/live.js',page)
        self.assertEqual(data['day'],'DEMO')
        self.assertTrue(all(row['ip'].startswith(('192.0.2.','198.51.100.','203.0.113.')) for row in data['points']))
        self.assertFalse(pathlib.Path(self.app.EVENTFILE).exists())

    def test_assets_and_map_data(self):
        svg=self.get('/assets/world.svg')
        self.assertGreater(len(ET.fromstring(svg).findall('{http://www.w3.org/2000/svg}path')),170)
        self.assertNotIn('<script',svg)
        self.assertIn('world-map',self.get('/assets/features.js'))
        day=datetime.date.today();ts=datetime.datetime.combine(day,datetime.time(12)).timestamp()
        with self.app.db_connect() as c:
            c.execute('INSERT INTO events VALUES (?,?,?,?)',(ts,'192.0.2.1','/','GET'))
            c.execute('INSERT INTO geo VALUES (?,?,?,?,?)',('192.0.2.1','Test country',52,21,ts))
        data=json.loads(self.get('/geo/data?day='+day.isoformat(),True))
        self.assertEqual(data['points'][0]['hour'],12)
        self.assertEqual(data['points'][0]['count'],1)
        self.assertIn('map-range',self.get('/geo',True))
        with self.assertRaises(urllib.error.HTTPError) as error:self.get('/geo/data?day=bad',True)
        self.assertEqual(error.exception.code,400);error.exception.close()

    def rule_fields(self,**extra):
        fields={'token':self.app.admin_token('watch-rules'),'name':'Test rule','kind':'path','path':'/backup.zip','window_seconds':'60','threshold':'1','action':'save'}
        fields.update(extra);return fields

    def test_rule_crud_and_alert(self):
        self.post_rule(self.rule_fields())
        self.app.log_event('192.0.2.1','/backup.zip','GET')
        alerts=self.app.rule_alerts()
        self.assertEqual(alerts[0][0],'watch:1')
        self.assertIn('192.0.2.1',alerts[0][1])
        self.assertIn('Test rule',self.get('/rules',True))
        self.post_rule({'token':self.app.admin_token('watch-rules'),'id':'1','action':'toggle'})
        self.assertEqual(self.app.rule_alerts(),[])
        self.post_rule({'token':self.app.admin_token('watch-rules'),'id':'1','action':'delete'})
        with self.app.db_connect() as c:self.assertEqual(c.execute('SELECT COUNT(*) FROM watch_rules').fetchone()[0],0)

    def test_rule_prefix_literal_wildcards_and_panels(self):
        self.app.change_rule({k:[v] for k,v in self.rule_fields(path='/foo%*').items()})
        self.app.log_event('192.0.2.1','/fooOTHER','GET')
        self.assertEqual(self.app.rule_alerts(),[])
        self.app.log_event('192.0.2.1','/foo%literal','GET')
        self.assertEqual(len(self.app.rule_alerts()),1)
        self.app.change_rule({k:[v] for k,v in self.rule_fields(kind='panels',threshold='3',name='Many panels').items()})
        for profile in ('router','camera','nas'):
            self.app.log_event('192.0.2.2','/traps/'+profile,'GET','',profile)
        self.assertIn('watch:2',dict(self.app.rule_alerts()))

    def test_rule_csrf_and_validation(self):
        with self.assertRaises(urllib.error.HTTPError) as error:self.post_rule(self.rule_fields(token='bad'))
        self.assertEqual(error.exception.code,403);error.exception.close()
        for fields in (self.rule_fields(path='bad'),self.rule_fields(threshold='0'),self.rule_fields(kind='panels',threshold='7')):
            with self.assertRaises(urllib.error.HTTPError) as error:self.post_rule(fields)
            self.assertEqual(error.exception.code,400);error.exception.close()
        with self.assertRaises(urllib.error.HTTPError) as error:self.get('/rules/save',True)
        self.assertEqual(error.exception.code,405);error.exception.close()

    def test_protected_new_routes(self):
        for path in ('/rules','/rules/save','/geo/data','/healthchecks'):
            with self.assertRaises(urllib.error.HTTPError) as error:self.get(path)
            self.assertEqual(error.exception.code,401);error.exception.close()

    def test_real_health_checks_and_stale_importer(self):
        self.app.PORT=self.server.server_port
        self.app.CONFIG['health_checks']['gatus_url']=self.base+'/health'
        self.app.command_output=lambda *args,**kwargs: json.dumps({'BackendState':'Running','TailscaleIPs':['100.64.1.2'],'Self':{'Online':True}})
        self.app.net_ports=lambda: ({self.app.ENDLESSH_PORT},collections.Counter())
        self.app.ENDLESSH_SUCCESS=time.time()
        checks=self.app.run_health_checks()
        self.assertTrue(all(row['ok'] for row in checks.values()))
        self.app.ENDLESSH_SUCCESS=time.time()-1000
        self.app.command_output=lambda *args,**kwargs: json.dumps({'BackendState':'Stopped'})
        checks=self.app.run_health_checks()
        self.assertFalse(checks['Tailscale']['ok']);self.assertFalse(checks['Endlessh']['ok'])
        self.assertIn('Sprawność usług',self.get('/healthchecks',True))

    def test_configuration_new_options(self):
        p=self.root/'new-config.json'
        for bad in ({'honeypots':{'enabled':['missing']}},{'honeypots':{'homepage':'missing'}},{'health_checks':{'gatus_url':'file:///etc/passwd'}},{'health_checks':{'timeout_seconds':0}},{'health_checks':{'gatus_url':'http://user:secret@localhost/'}}):
            p.write_text(json.dumps(bad))
            with self.subTest(bad=bad),self.assertRaises(ValueError):self.app.load_config(p)
        self.app.CONFIG['demo_enabled']=False
        with self.assertRaises(urllib.error.HTTPError) as error:self.get('/demo')
        self.assertEqual(error.exception.code,404);error.exception.close()

if __name__=='__main__':unittest.main()
