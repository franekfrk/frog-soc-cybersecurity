import datetime
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import unittest
import test_credentials

class AnalyticsTests(unittest.TestCase):
    def setUp(self):
        test_credentials.CredentialTests.setUp(self)

    def test_statistics_and_secret_isolation(self):
        for ip in ('192.0.2.1','::ffff:192.0.2.1','192.0.2.2'):
            self.app.save_credentials(ip,'<root>','private-test-password')
        data=self.app.credential_statistics()
        self.assertEqual((data['total'],data['ips'],data['users'],data['passwords']),(3,2,1,1))
        self.assertEqual(data['pairs'][0],('<root>','private-test-password',3,2))
        self.assertIn('&lt;root&gt;',self.app.credential_stats_page())
        with self.app.db_connect() as c:
            self.assertFalse(c.execute("SELECT name FROM sqlite_master WHERE name='submissions'").fetchall())

    def test_campaigns_thresholds_paths_and_mapped_ips(self):
        for ip in ('192.0.2.1','::ffff:192.0.2.1','192.0.2.2'):
            self.app.save_credentials(ip,'router','example-only')
            self.app.log_event(ip,'/wp-login.php' if ip=='192.0.2.1' else '/wp-admin/','GET')
        credentials,paths=self.app.campaign_patterns()
        self.assertEqual(len(credentials),1)
        self.assertEqual(credentials[0]['ips'],2)
        self.assertEqual(paths[0]['family'],'WordPress')
        self.assertEqual(len(paths[0]['peers']),2)
        self.app.CONFIG['campaigns']['min_ips']=3
        self.assertEqual(self.app.campaign_patterns(),([],[]))

    def token_fields(self,action='selected',ids=None):
        with self.app.credentials_connect() as c:
            maximum=c.execute('SELECT COALESCE(MAX(id),0) FROM submissions').fetchone()[0]
        return {'token':[self.app.deletion_token(maximum)],'action':[action],'confirm':['USUN'],'id':[str(value) for value in (ids or [])]}

    def test_selected_delete_and_stale_snapshot(self):
        self.app.save_credentials('192.0.2.1','one','a')
        self.app.save_credentials('192.0.2.1','two','b')
        fields=self.token_fields(ids=[1])
        self.assertEqual(self.app.delete_credentials(fields),1)
        fields=self.token_fields(action='all')
        time.sleep(.002)
        self.app.save_credentials('192.0.2.1','new','c')
        self.assertEqual(self.app.delete_credentials(fields),1)
        with self.app.credentials_connect() as c:
            self.assertEqual(c.execute('SELECT username FROM submissions').fetchall(),[('new',)])

    def test_confirmation_and_csrf_expiry(self):
        self.app.save_credentials('192.0.2.1','one','a')
        fields=self.token_fields(action='all')
        fields['confirm']=['yes']
        with self.assertRaises(ValueError): self.app.delete_credentials(fields)
        fields['confirm']=['USUN'];fields['token'][0]+='x'
        with self.assertRaises(PermissionError): self.app.delete_credentials(fields)
        token=self.app.deletion_token(1,now=10000)
        with self.assertRaises(PermissionError): self.app.validate_deletion_token(token,now=12000)
        self.assertEqual(self.app.validate_deletion_token(token,now=10001),(1,10000))

    def test_http_protection_and_deletion(self):
        self.app.save_credentials('192.0.2.1','one','example')
        for path in ('/credential-stats','/campaigns','/reports','/credentials/delete'):
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(self.base+path)
            self.assertEqual(error.exception.code,401);error.exception.close()
        with urllib.request.urlopen(urllib.request.Request(self.base+'/credentials',headers=self.auth)) as response:
            page=response.read().decode()
        token=re.search('name="token" value="([^"]+)"',page).group(1)
        data=urllib.parse.urlencode({'token':token,'confirm':'USUN','action':'selected','id':1}).encode()
        with urllib.request.urlopen(urllib.request.Request(self.base+'/credentials/delete',data=data,headers=self.auth)) as response:
            self.assertIn('/credentials?deleted=1',response.url)
        with self.app.credentials_connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM submissions').fetchone()[0],0)
        for path,code in [('/credentials/delete',405)]:
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(urllib.request.Request(self.base+path,headers=self.auth))
            self.assertEqual(error.exception.code,code);error.exception.close()
        for path in ('/credential-stats','/campaigns','/reports'):
            with urllib.request.urlopen(urllib.request.Request(self.base+path,headers=self.auth)) as response:
                self.assertEqual(response.status,200)

    def test_bad_post_token_does_not_delete(self):
        self.app.save_credentials('192.0.2.1','one','example')
        data=urllib.parse.urlencode({'token':'bad','confirm':'USUN','action':'all'}).encode()
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(urllib.request.Request(self.base+'/credentials/delete',data=data,headers=self.auth))
        self.assertEqual(error.exception.code,403);error.exception.close()
        self.assertEqual(self.app.credential_statistics()['total'],1)

    def test_daily_report_window_counts_and_no_credentials(self):
        day=datetime.date(2026,10,21)
        start=datetime.datetime(2026,10,21).timestamp()
        with self.app.db_connect() as c:
            c.executemany('INSERT INTO events VALUES (?,?,?,?)',[(start-1,'192.0.2.1','/','GET'),(start+1,'192.0.2.1','/','GET'),(start+1,'192.0.2.2','/','GET')])
            c.execute('INSERT INTO endlessh_sessions VALUES (?,?,?,?,?,?,?)',('test','192.0.2.3',1234,1,start+2,start+12,10))
        self.app.save_credentials('192.0.2.1','SECRET_USER','SECRET_PASSWORD')
        with self.app.credentials_connect() as c: c.execute('UPDATE submissions SET ts=?',(start+3,))
        text=self.app.daily_report_text(day)
        self.assertIn('HTTP: 2',text)
        self.assertIn('Sesje Endlessh: 1',text)
        self.assertIn('Formularze pułapki: 1',text)
        self.assertIn('Nowe IP w zachowanej historii: 2',text)
        self.assertNotIn('SECRET',text)

    def test_daily_schedule_retry_and_persistence(self):
        sent=[]
        self.app.webhooks_notify=lambda message: sent.append(message) or False
        before=datetime.datetime(2026,10,22,19,59).timestamp()
        due=datetime.datetime(2026,10,22,20,0).timestamp()
        self.assertFalse(self.app.maybe_send_daily_report(before))
        self.assertEqual(sent,[])
        self.assertFalse(self.app.maybe_send_daily_report(due))
        self.app.webhooks_notify=lambda message: sent.append(message) or True
        self.assertTrue(self.app.maybe_send_daily_report(due+60))
        self.assertFalse(self.app.maybe_send_daily_report(due+120))
        self.assertEqual(len(sent),2)
        with self.app.db_connect() as c:
            self.assertEqual(self.app.meta_get(c,'daily_report_last'),'2026-10-21')
        self.app.CONFIG['daily_report']['enabled']=False
        self.assertFalse(self.app.maybe_send_daily_report(due+86400))

    def test_new_configuration_validation(self):
        import json
        p=self.root/'test-config.json'
        for config in ({'daily_report':{'hour':24}},{'daily_report':{'minute':60}},{'campaigns':{'min_ips':1}},{'campaigns':{'window_hours':0}}):
            p.write_text(json.dumps(config))
            with self.subTest(config=config),self.assertRaises(ValueError): self.app.load_config(p)
        p.write_text(json.dumps({'daily_report':{'hour':0,'minute':0}}))
        self.assertEqual(self.app.load_config(p)['daily_report']['hour'],0)

if __name__=='__main__': unittest.main()
