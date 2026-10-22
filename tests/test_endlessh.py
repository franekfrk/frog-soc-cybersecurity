import datetime
import pathlib
import tempfile
import types
import unittest

class EndlesshTests(unittest.TestCase):
    def setUp(self):
        script = pathlib.Path(__file__).resolve().parents[1] / 'update-frog-soc-4.sh'
        source = script.read_text().split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        self.app = types.ModuleType('frog_test')
        exec(compile(source, str(script), 'exec'), self.app.__dict__)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)
        self.app.DB = str(self.root / 'history.sqlite3')
        self.log = self.root / 'endlessh.log'
        self.app.ENDLESSH_LOGS = (str(self.root / '*.log*'),)

    def line(self, kind='ACCEPT', stamp='2026-10-22T12:00:00.000Z', ip='192.0.2.10', port=50001):
        return f'{stamp} {kind} host={ip} port={port} fd=7 ' + ('time=2.125 bytes=32\n' if kind == 'CLOSE' else 'n=1/4096\n')

    def rows(self):
        with self.app.db_connect() as c:
            return c.execute('SELECT ip,port,started,ended,seconds FROM endlessh_sessions ORDER BY started').fetchall()

    def test_pair_exact_duration(self):
        self.log.write_text(self.line()+self.line('CLOSE', '2026-10-22T12:00:02.125Z'))
        self.app.import_endlessh_logs()
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0][4], 2.125)
        self.assertAlmostEqual(self.rows()[0][3]-self.rows()[0][2], 2.125)

    def test_persistent_cursor_and_rotation(self):
        self.log.write_text(self.line())
        self.app.import_endlessh_logs()
        self.log.rename(str(self.log)+'.1')
        self.log.write_text(self.line('CLOSE', '2026-10-22T12:00:02.125Z'))
        self.app.import_endlessh_logs()
        self.app.import_endlessh_logs()
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0][4], 2.125)

    def test_partial_line(self):
        line = self.line()
        self.log.write_text(line[:-4])
        self.app.import_endlessh_logs()
        self.assertEqual(self.rows(), [])
        with self.log.open('a') as f:
            f.write(line[-4:])
        self.app.import_endlessh_logs()
        self.assertEqual(len(self.rows()), 1)

    def test_close_only_ipv6(self):
        self.log.write_text(self.line('CLOSE', ip='2001:db8::10'))
        self.app.import_endlessh_logs()
        self.assertEqual(self.rows()[0][0], '2001:db8::10')
        self.assertEqual(self.rows()[0][4], 2.125)

    def test_parallel_sessions(self):
        self.log.write_text(self.line()+self.line(port=50002)+self.line('CLOSE', '2026-10-22T12:00:02.125Z', port=50002))
        self.app.import_endlessh_logs()
        rows = {r[1]: r for r in self.rows()}
        self.assertIsNone(rows[50001][3])
        self.assertEqual(rows[50002][4], 2.125)

    def test_syslog_rollover(self):
        ref = datetime.datetime(2027, 1, 1).timestamp()
        line = 'Dec 31 23:59:59 host endlessh[12]: ACCEPT host=192.0.2.1 port=1234 fd=3 n=1/10'
        record = self.app.endlessh_record(line, ref)
        self.assertEqual(datetime.datetime.fromtimestamp(record[5]).year, 2026)
        self.assertIsNone(self.app.endlessh_record(line.replace('endlessh[12]', 'sshd'), ref))

    def test_truncation_duplicates(self):
        self.log.write_text(self.line()+self.line())
        self.app.import_endlessh_logs()
        self.assertEqual(len(self.rows()), 1)
        self.log.write_text(self.line('CLOSE', '2026-10-22T12:00:02.125Z'))
        self.app.import_endlessh_logs()
        self.assertEqual(self.rows()[0][4], 2.125)

    def test_panel_pagination(self):
        self.app.ssh_failures = lambda: {'top_ips': [], 'count': 0}
        self.app.net_ports = lambda: ({41888}, {41888: 1})
        self.assertIn('Brak zapisanych połączeń', self.app.ssh_page())
        self.log.write_text(''.join(self.line(port=51000+i) for i in range(51)))
        self.app.import_endlessh_logs()
        self.assertIn('brak CLOSE', self.app.ssh_page())
        self.assertIn('Strona 1 / 2', self.app.ssh_page())
        self.assertIn('Strona 2 / 2', self.app.ssh_page(999))
        self.assertIn('Strona 1 / 2', self.app.ssh_page(-1))

    def test_missing_logs(self):
        self.app.import_endlessh_logs()
        self.assertIn('Nie znaleziono', self.app.ENDLESSH_ERROR)

if __name__ == '__main__':
    unittest.main()
