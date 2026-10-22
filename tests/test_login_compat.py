import html.parser
import urllib.error
import urllib.parse
import urllib.request
import unittest
import test_credentials


class FormParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.action=None
        self.inputs={}

    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='form':
            self.action=attrs.get('action')
        if tag=='input' and attrs.get('name'):
            self.inputs[attrs['name']]=attrs


class LoginCompatibilityTests(unittest.TestCase):
    def setUp(self):
        test_credentials.CredentialTests.setUp(self)

    def post(self,path,fields,auth=False):
        request=urllib.request.Request(self.base+path,data=urllib.parse.urlencode(fields,doseq=True).encode(),headers=self.auth if auth else {})
        with urllib.request.urlopen(request) as response:
            return response.read().decode()

    def rows(self):
        with self.app.credentials_connect() as db:
            return db.execute('SELECT username,password,profile FROM submissions ORDER BY id').fetchall()

    def test_rendered_forms_roundtrip_all_profiles(self):
        for profile,path in self.app.TRAP_PATHS.items():
            with urllib.request.urlopen(self.base+path) as response:
                parser=FormParser();parser.feed(response.read().decode())
            user,password=self.app.TRAP_FORM_FIELDS[profile]
            self.assertEqual(parser.action,self.app.TRAP_LOGIN_PATHS[profile])
            self.assertEqual(parser.inputs[user]['autocomplete'],'username')
            self.assertEqual(parser.inputs[password]['autocomplete'],'current-password')
            self.assertEqual(parser.inputs[password]['type'],'password')
            result=self.post(parser.action,{user:'synthetic-'+profile,password:'synthetic-secret-'+profile})
            self.assertIn('Sign-in failed',result)
            self.assertNotIn('synthetic-secret-',result)
        self.assertEqual(self.rows(),[('synthetic-'+p,'synthetic-secret-'+p,p) for p in self.app.TRAP_PATHS])

    def test_device_identity_and_theme_are_consistent(self):
        with urllib.request.urlopen(self.base+'/') as response:hub=response.read().decode()
        for profile,device in self.app.TRAP_DEVICES.items():
            self.assertIn(device['model'],hub)
            self.assertIn(device['platform'],hub)
            self.assertIn(device['kind'],hub)
            with urllib.request.urlopen(self.base+self.app.TRAP_PATHS[profile]) as response:page=response.read().decode()
            self.assertIn(device['model'],page)
            self.assertIn(device['platform'],page)
            self.assertIn(self.app.TRAP_THEMES[profile],page)
        with urllib.request.urlopen(self.base+'/config.json') as response:
            import json
            config=json.load(response)
        self.assertEqual(config['gateway'],self.app.TRAP_DEVICES['router']['model'])
        self.assertEqual(config['storage'],'Nextcloud')

    def test_common_aliases_and_disabled_profiles(self):
        for path,profile in self.app.TRAP_ALIASES.items():
            result=self.post(path+'/',{'user':'alias-user','pass':'alias-secret'})
            self.assertIn('Sign-in failed',result)
            self.assertEqual(self.rows()[-1],('alias-user','alias-secret',profile))
        count=len(self.rows())
        self.app.CONFIG['honeypots']['enabled']=['router']
        for path in ('/administrator','/admin/login','/wp-login.php','/camera/login.cgi','/index.php/login','/api/auth/login'):
            with self.assertRaises(urllib.error.HTTPError) as error:self.post(path,{'log':'ignored','pwd':'ignored'})
            self.assertEqual(error.exception.code,404);error.exception.close()
        self.assertEqual(len(self.rows()),count)

    def test_field_aliases_precedence_and_empty_values(self):
        pairs=[('username','password'),('user','pass'),('login','passwd'),('log','pwd'),('email','password'),('luci_username','luci_password')]
        for user,password in pairs:
            self.post('/login.php',{user:'alias-user',password:'alias-secret'})
            self.assertEqual(self.rows()[-1],('alias-user','alias-secret','router'))
        self.post('/wp-login.php',{'log':'wp-user','pwd':'wp-secret','username':'other','password':'other'})
        self.assertEqual(self.rows()[-1],('wp-user','wp-secret','wordpress'))
        self.post('/wp-login.php',{'log':['','second'],'pwd':'','username':'fallback','password':'fallback'})
        self.assertEqual(self.rows()[-1],('','','wordpress'))
        self.post('/camera/login.cgi',{'user':'only-user'})
        self.assertEqual(self.rows()[-1],('only-user','','camera'))
        count=len(self.rows());self.post('/login',{'unrelated':'ignored'})
        self.assertEqual(len(self.rows()),count)

    def test_alternate_fields_keep_limits_and_log_isolation(self):
        self.post('/wp-login.php',{'log':'u'*300,'pwd':'p'*700})
        self.assertEqual(self.rows(),[('u'*256,'p'*512,'wordpress')])
        for fields,expected in [({'log':'u','pwd':'p'*4096},413),({**{'field'+str(i):'x' for i in range(15)},'log':'u','pwd':'p'},400)]:
            with self.assertRaises(urllib.error.HTTPError) as error:self.post('/wp-login.php',fields)
            self.assertEqual(error.exception.code,expected);error.exception.close()
        self.assertEqual(len(self.rows()),1)
        with open(self.app.EVENTFILE) as log:self.assertNotIn('p'*512,log.read())

    def test_get_disabled_capture_and_admin_auth_are_not_collected(self):
        with urllib.request.urlopen(self.base+'/wp-login.php?log=synthetic-user&pwd=synthetic-secret') as response:
            response.read()
        self.app.CONFIG['capture_credentials']=False
        self.post('/wp-login.php',{'log':'synthetic-user','pwd':'synthetic-secret'})
        self.app.CONFIG['capture_credentials']=True
        for path in ('/soc','/credentials','/rules/save'):
            with self.assertRaises(urllib.error.HTTPError) as error:self.post(path,{'log':'synthetic-user','pwd':'synthetic-secret'})
            self.assertEqual(error.exception.code,401);error.exception.close()
        self.assertEqual(self.rows(),[])
        with urllib.request.urlopen(urllib.request.Request(self.base+'/soc',headers=self.auth)) as response:
            response.read()
        self.assertEqual(self.rows(),[])


if __name__=='__main__':unittest.main()
