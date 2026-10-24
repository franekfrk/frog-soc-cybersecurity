import contextlib,logging
import importlib.util,os,pathlib,socket,sqlite3,subprocess,sys,tempfile,time,unittest
try: import paramiko
except ImportError: paramiko=None

@unittest.skipIf(paramiko is None,'Paramiko required: run in /tmp/frog-ssh-test venv')
class SSHTests(unittest.TestCase):
    def setUp(self):
        logging.getLogger('paramiko').setLevel(logging.CRITICAL)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.state=pathlib.Path(self.temp.name)/'state'
        with socket.socket() as s:s.bind(('127.0.0.1',0));self.port=s.getsockname()[1]
        script=pathlib.Path(__file__).resolve().parents[1]/'deploy/ssh_trap.py'
        self.proc=subprocess.Popen([sys.executable,str(script),'--port',str(self.port),'--state',str(self.state)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1',self.port),timeout=.2):break
            except OSError:
                if self.proc.poll() is not None:self.fail('SSH server failed to start')
                time.sleep(.05)
        else:self.fail('SSH server startup timeout')
    def stop(self):
        self.proc.terminate()
        try:self.proc.wait(3)
        except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait()
    def client(self):
        t=paramiko.Transport(socket.create_connection(('127.0.0.1',self.port),timeout=3))
        self.addCleanup(t.close);t.start_client(timeout=5)
        self.assertTrue(t.remote_version.startswith('SSH-2.0-OpenSSH_'))
        return t
    def test_real_password_and_keyboard_interactive_always_denied(self):
        t=self.client()
        with self.assertRaises(paramiko.AuthenticationException):t.auth_password('synthetic-ssh','synthetic-password',fallback=False)
        self.assertFalse(t.is_authenticated())
        t.close();t=self.client()
        with self.assertRaises(paramiko.AuthenticationException):t.auth_interactive('interactive-user',lambda *args:['interactive-password'])
        self.assertFalse(t.is_authenticated())
        with contextlib.closing(sqlite3.connect(self.state/'attempts.sqlite3')) as c, c:
            rows=c.execute('SELECT username,password FROM attempts ORDER BY ts').fetchall()
        self.assertEqual(rows,[('synthetic-ssh','synthetic-password'),('interactive-user','interactive-password')])
        self.assertEqual((self.state/'attempts.sqlite3').stat().st_mode&0o777,0o600)
        self.assertNotIn('synthetic-password',(self.state/'sessions.log').read_text())
    def test_none_publickey_channels_and_forwarding_denied(self):
        t=self.client()
        with self.assertRaises(paramiko.AuthenticationException):t.auth_none('root')
        with self.assertRaises(paramiko.AuthenticationException):t.auth_publickey('root',paramiko.RSAKey.generate(2048))
        with self.assertRaises((paramiko.SSHException,EOFError)):t.open_session(timeout=2)
        t.close()
        spec=importlib.util.spec_from_file_location('trap',pathlib.Path(__file__).resolve().parents[1]/'deploy/ssh_trap.py')
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        server=mod.PasswordTrap(self.state,'127.0.0.1')
        self.assertFalse(server.check_channel_exec_request(None,b'id'))
        self.assertFalse(server.check_channel_shell_request(None))
        self.assertFalse(server.check_port_forward_request('127.0.0.1',12345))
        self.assertFalse(server.check_channel_subsystem_request(None,'sftp'))
    def test_capture_attempt_cap(self):
        t=self.client()
        for i in range(6):
            with self.assertRaises(paramiko.AuthenticationException):t.auth_password('u','p'+str(i),fallback=False)
        time.sleep(.4)
        self.assertFalse(t.is_active())
        with contextlib.closing(sqlite3.connect(self.state/'attempts.sqlite3')) as c, c:self.assertEqual(c.execute('SELECT COUNT(*) FROM attempts').fetchone()[0],6)
