import contextlib
import base64
import csv
import io
import json
import os
import pathlib
import sqlite3
import threading
import time
import urllib.error
import urllib.request
import unittest
import test_endlessh

class FeatureTests(unittest.TestCase):
    line = test_endlessh.EndlesshTests.line
    rows = test_endlessh.EndlesshTests.rows
    def setUp(self):
        test_endlessh.EndlesshTests.setUp(self)
        self.app.ROOT = str(self.root)
        self.app.EVENTFILE = str(self.root/'events.jsonl')
        self.app.PASSWORD_FILE = str(self.root/'password')
        self.app.CONFIG_PATH = str(self.root/'config.json')
        self.app.CREDENTIALS_DB = str(self.root/'credentials.sqlite3')
        self.app.CONFIG['geo_enabled'] = False
        self.app.initialize_db()

    def seed(self):
        self.log.write_text(self.line(ip='192.0.2.10')+self.line('CLOSE','2026-10-22T12:00:02.125Z',ip='192.0.2.10')+self.line(stamp='2026-10-23T12:00:00.000Z',ip='2001:db8::1',port=50002))
        self.app.import_endlessh_logs()

    def test_config_validation(self):
        config=self.root/'settings.json'
        config.write_text(json.dumps({'http_port':32000,'endlessh_port':42000,'alerts':{'cooldown_seconds':1800}}))
        loaded=self.app.load_config(config)
        self.assertEqual(loaded['http_port'],32000)
        self.assertEqual(loaded['alerts']['cooldown_seconds'],1800)
        self.assertEqual(loaded['alerts']['ram_percent'],85)
        for bad in ({'http_port':0},{'http_port':41888},{'page_size':999},{'alerts':{'cooldown_seconds':0}},{'http_port':'1234'},{'x':1},{'trusted_networks':['bad']},{'alerts':{'ram_percent':101}}):
            config.write_text(json.dumps(bad))
            with self.subTest(bad=bad), self.assertRaises(ValueError): self.app.load_config(config)

    def test_filters_csv_sort_ip_detail(self):
        self.seed()
        rows,total,_,_=self.app.session_rows({'ip':'192.0.2.10','from':'2026-10-22','to':'2026-10-22','status':'closed','min_seconds':'2','sort':'longest'})
        self.assertEqual(total,1)
        self.assertEqual(rows[0][4],2.125)
        self.assertEqual(self.app.session_rows({'status':'pending'})[1],1)
        exported=list(csv.reader(io.StringIO(self.app.endlessh_csv({'ip':'2001:db8::1'}).lstrip('\ufeff'))))
        self.assertEqual(len(exported),2)
        self.assertEqual(exported[1][0],'2001:db8::1')
        self.assertIn('Łączny czas',self.app.ip_page('192.0.2.10'))
        for params in ({'from':'bad'},{'from':'2026-10-23','to':'2026-10-22'},{'ip':"' OR 1=1"},{'min_seconds':'nan'},{'sort':'DROP TABLE'},{'status':'broken'}):
            with self.subTest(params=params), self.assertRaises(ValueError): self.app.session_rows(params)

    def test_mapped_ipv4_filter_and_escaping(self):
        self.log.write_text(self.line(ip='::ffff:192.0.2.10'))
        self.app.import_endlessh_logs()
        self.assertEqual(self.app.session_rows({'ip':'192.0.2.10'})[1],1)
        self.app.log_event('192.0.2.10','/<script>alert(1)</script>','GET')
        activity=self.app.activity_page({'ip':'192.0.2.10'})
        self.assertIn('&lt;script&gt;',activity)
        self.assertNotIn('/<script>alert',activity)

    def test_auth_import_dedup_and_timeline(self):
        auth=self.root/'auth.log'
        auth.write_text('Oct 22 13:00:00 machine sshd[1]: Failed password for invalid user bob from 192.0.2.5 port 555 ssh2\n')
        self.app.CONFIG['auth_logs']=[str(auth)]
        self.app.import_auth_logs();self.app.import_auth_logs()
        with self.app.db_connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM auth_events').fetchone()[0],1)
        self.assertIn('192.0.2.5',self.app.activity_page())
        self.assertNotIn('bob',self.app.activity_page())

    def test_alert_identity_persistence_and_recovery(self):
        sent=[]
        self.app.webhooks_notify=lambda msg: sent.append(msg) or True
        self.app.dispatch_alerts([('http:hour','100 requests')],10000)
        self.app.dispatch_alerts([('http:hour','101 requests')],10001)
        self.assertEqual(len(sent),1)
        self.app.dispatch_alerts([('http:hour','110 requests')],11000)
        self.assertEqual(len(sent),2)
        self.app.dispatch_alerts([],11001)
        self.app.dispatch_alerts([],11002)
        self.assertEqual(len(sent),3)
        self.assertIn('Ustąpił',sent[-1])

    def test_failed_webhook_retries(self):
        attempts=[]
        self.app.webhooks_notify=lambda message: attempts.append(message) and False
        self.app.dispatch_alerts([('disk','full')],10000)
        self.app.dispatch_alerts([('disk','full')],10001)
        self.assertEqual(len(attempts),2)

    def test_exact_hour_from_database(self):
        now=time.time()
        with self.app.db_connect() as c:
            c.executemany('INSERT INTO events VALUES (?,?,?,?)',[(now,'192.0.2.1','/','GET')]*700)
        self.assertEqual(self.app.analytics()[3],700)
        fake={'mem':{'used':1,'total':100},'disk':{'used':1,'total':100},'services':[]}
        self.assertIn('http:hour',dict(self.app.alert_candidates(fake)))

    def test_retention_backup_and_xp_survive(self):
        self.app.log_event('192.0.2.1','/','GET')
        self.log.write_text(self.line())
        self.app.import_endlessh_logs()
        with self.app.db_connect() as c:
            before=c.execute('SELECT key,value FROM meta WHERE key LIKE "%lifetime" ORDER BY key').fetchall()
            c.execute('UPDATE events SET ts=0')
            c.execute('UPDATE endlessh_sessions SET started=0')
        self.app.maintenance_once()
        with self.app.db_connect() as c:
            after=c.execute('SELECT key,value FROM meta WHERE key LIKE "%lifetime" ORDER BY key').fetchall()
            self.assertEqual(c.execute('SELECT COUNT(*) FROM endlessh_sessions').fetchone()[0],0)
        self.assertEqual(before,after)
        backups=list((self.root/'backups'/'automatic').glob('*.sqlite3'))
        self.assertEqual(len(backups),1)
        self.assertEqual(backups[0].stat().st_mode&0o777,0o600)
        with contextlib.closing(sqlite3.connect(backups[0])) as c: self.assertEqual(c.execute('PRAGMA integrity_check').fetchone()[0],'ok')
        self.assertIn('15 XP',self.app.frog4())

    def test_real_http_auth_filters_export_and_new_pages(self):
        self.seed()
        pathlib.Path(self.app.PASSWORD_FILE).write_text('test-only-password')
        server=self.app.Server(('127.0.0.1',0),self.app.Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        base='http://127.0.0.1:'+str(server.server_port)
        auth='Basic '+base64.b64encode(b'frog:test-only-password').decode()
        for path,marker in [('/soc','Aktywność'),('/ssh?sort=longest','Port źródłowy'),('/ssh.csv?status=closed','2.125'),('/activity','Wspólna aktywność'),('/ip?ip=192.0.2.10','Łączny czas'),('/settings','6.2'),('/assets/live.js','setInterval'),('/frog','XP')]:
            with self.subTest(path=path):
                with urllib.request.urlopen(urllib.request.Request(base+path,headers={'Authorization':auth})) as response:
                    self.assertIn(marker,response.read().decode())
        for path,code in [('/ssh',401),('/ssh?ip=invalid',400),('/ssh?from=bad',400)]:
            headers={} if code==401 else {'Authorization':auth}
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(urllib.request.Request(base+path,headers=headers))
            self.assertEqual(error.exception.code,code)
            error.exception.close()
        self.app.CONFIG['trusted_networks']=[]
        self.assertFalse(self.app.trusted('192.0.2.1'))
        self.assertTrue(self.app.trusted('127.0.0.1'))

if __name__=='__main__': unittest.main()
