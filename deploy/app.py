#!/usr/bin/env python3
"""Frog SOC 6.0; stdlib-only Alpine/OpenRC mini SOC."""
import base64
import collections
import copy
import csv
import io
import logging
import datetime
import html
import hashlib
import hmac
import http.server
import ipaddress
import json
import glob
import sqlite3
import urllib.request
import urllib.error
import math
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
from urllib.parse import urlsplit, parse_qs, urlencode

VERSION = '6.0'
DEFAULT_CONFIG = {
    'capture_credentials': True, 'listen_host': '0.0.0.0', 'http_port': 31888, 'endlessh_port': 41888,
    'endlessh_logs': ['/var/log/endlessh.log*'],
    'auth_logs': ['/var/log/auth.log', '/var/log/secure', '/var/log/messages'],
    'trusted_networks': ['100.64.0.0/10'], 'page_size': 50,
    'import_interval': 5, 'refresh_seconds': 15, 'geo_enabled': True,
    'required_services': ['Frog SOC', 'Endlessh', 'Tailscale'],
    'alerts': {'enabled': True, 'cooldown_seconds': 900, 'interval_seconds': 60,
               'ram_percent': 85, 'disk_percent': 85, 'http_hour': 100,
               'ip_hour': 50, 'ssh_hour': 10, 'burst_factor': 3,
               'endlessh_record_seconds': 300, 'recovery': True},
    'retention': {'http_days': 90, 'http_rows': 30000, 'endlessh_days': 90,
                  'endlessh_rows': 100000, 'auth_days': 30, 'credentials_days': 7, 'credentials_rows': 10000},
    'maintenance': {'interval_seconds': 3600, 'backup_hours': 24, 'backup_keep': 7},
    'daily_report': {'enabled': True, 'hour': 20, 'minute': 0},
    'campaigns': {'window_hours': 24, 'min_ips': 2, 'min_attempts': 3},
    'honeypots': {'enabled': ['router', 'camera', 'nas', 'admin', 'wordpress', 'api'], 'homepage': 'hub'},
    'health_checks': {'gatus_url': 'http://127.0.0.1:21888/health', 'timeout_seconds': 2, 'interval_seconds': 30, 'endlessh_stale_seconds': 120},
    'demo_enabled': True
}
ROOT = os.environ.get('FROG_ROOT', '/opt/frog-soc')
CONFIG_PATH = os.environ.get('FROG_CONFIG', ROOT + '/config.json')


def load_config(path):
    config = copy.deepcopy(DEFAULT_CONFIG)
    if os.path.exists(path):
        with open(path, encoding='utf-8') as f:
            supplied = json.load(f)
        def merge(target, data):
            if not isinstance(data, dict):
                raise ValueError('Konfiguracja musi być obiektem JSON')
            for key, value in data.items():
                if key not in target:
                    raise ValueError('Nieznana opcja: '+key)
                default = target[key]
                if isinstance(default, dict):
                    merge(default, value)
                elif type(value) is not type(default):
                    raise ValueError('Nieprawidłowy typ opcji: '+key)
                else:
                    target[key] = value
        merge(config, supplied)
    for key in ('http_port', 'endlessh_port'):
        if not 1024 <= config[key] <= 65535:
            raise ValueError(key+': wymagany port 1024–65535')
    if config['http_port'] == config['endlessh_port']:
        raise ValueError('Port Frog i Endlessh muszą być różne')
    if not 1 <= config['page_size'] <= 200:
        raise ValueError('page_size: wymagane 1–200')
    for key in ('import_interval', 'refresh_seconds'):
        if config[key] < 1:
            raise ValueError(key+': wymagana dodatnia wartość')
    for group in ('alerts', 'retention', 'maintenance'):
        for key, value in config[group].items():
            if type(value) is int and value < 1:
                raise ValueError(group+'.'+key+': wymagana dodatnia wartość')
    if not 0 <= config['daily_report']['hour'] <= 23 or not 0 <= config['daily_report']['minute'] <= 59:
        raise ValueError('daily_report: nieprawidłowa godzina/minuta')
    for key,value in config['campaigns'].items():
        if value < (2 if key == 'min_ips' else 1):
            raise ValueError('campaigns.'+key+': zbyt mała wartość')
    profiles={'router','camera','nas','admin','wordpress','api'}
    if not all(isinstance(v,str) for v in config['honeypots']['enabled']) or not set(config['honeypots']['enabled']) <= profiles or not config['honeypots']['enabled'] or len(set(config['honeypots']['enabled']))!=len(config['honeypots']['enabled']):
        raise ValueError('Nieprawidłowe profile pułapek')
    if config['honeypots']['homepage'] not in ['hub']+config['honeypots']['enabled']:
        raise ValueError('Nieprawidłowa strona główna pułapki')
    for key in ('timeout_seconds','interval_seconds','endlessh_stale_seconds'):
        if not 1 <= config['health_checks'][key] <= 3600:
            raise ValueError('Nieprawidłowy interwał health_checks')
    url=config['health_checks']['gatus_url']
    if url and (urlsplit(url).scheme not in ('http','https') or not urlsplit(url).hostname or urlsplit(url).username or len(url)>512):
        raise ValueError('Nieprawidłowy gatus_url')
    for key in ('ram_percent', 'disk_percent'):
        if config['alerts'][key] > 100:
            raise ValueError(key+': maksimum 100')
    for key in ('endlessh_logs', 'auth_logs', 'trusted_networks', 'required_services'):
        if not all(isinstance(v, str) and v for v in config[key]):
            raise ValueError('Nieprawidłowa lista: '+key)
    for network in config['trusted_networks']:
        ipaddress.ip_network(network)
    return config


CONFIG = load_config(CONFIG_PATH)
EVENTFILE = ROOT + '/events.jsonl'
PASSWORD_FILE = ROOT + '/.soc-password'
PORT = CONFIG['http_port']
ENDLESSH_PORT = CONFIG['endlessh_port']
EVENTS = collections.deque(maxlen=600)
LOCK = threading.Lock()
BOOT = time.time()
CACHE = {'at': 0, 'data': None}
MAX_ACTIVE = threading.BoundedSemaphore(12)
DB = ROOT + '/soc-history.sqlite3'
CREDENTIALS_DB = ROOT + '/honeypot-credentials.sqlite3'
WEBHOOK_FILE = ROOT + '/.discord-webhook'
DB_LOCK = threading.Lock()
GEO_LOCK = threading.Lock()
ALERT_COOLDOWN = CONFIG['alerts']['cooldown_seconds']
GEO_REFRESH = 86400 * 30
ENDLESSH_ERROR = ''
ENDLESSH_UPDATED = 0
ENDLESSH_SUCCESS = 0
ENDLESSH_LOGS = CONFIG['endlessh_logs']
MAINTENANCE_ERROR = ''
AUTH_ERROR = ''
CSRF_KEY = secrets.token_bytes(32)
REPORT_LOCK = threading.Lock()
HEALTH_LOCK = threading.Lock()
HEALTH_STATE = {}
ASSET_DIR = os.path.dirname(globals().get('__file__', ROOT+'/app.py'))


class SOCConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def db_connect():
    c = sqlite3.connect(DB, timeout=3, factory=SOCConnection)
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA busy_timeout=3000')
    c.execute('CREATE TABLE IF NOT EXISTS events (ts INTEGER, ip TEXT, path TEXT, method TEXT)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_ts ON events(ts)')
    c.execute('CREATE TABLE IF NOT EXISTS geo (ip TEXT PRIMARY KEY, country TEXT, lat REAL, lon REAL, checked INTEGER)')
    c.execute('CREATE TABLE IF NOT EXISTS endlessh_sessions (id TEXT PRIMARY KEY, ip TEXT, port INTEGER, fd INTEGER, started REAL, ended REAL, seconds REAL)')
    c.execute('CREATE INDEX IF NOT EXISTS endlessh_started ON endlessh_sessions(started)')
    c.execute('CREATE TABLE IF NOT EXISTS endlessh_seen (id TEXT PRIMARY KEY, ts REAL)')
    if 'ts' not in {row[1] for row in c.execute('PRAGMA table_info(endlessh_seen)')}:
        c.execute('ALTER TABLE endlessh_seen ADD COLUMN ts REAL')
    c.execute('CREATE TABLE IF NOT EXISTS endlessh_offsets (path TEXT PRIMARY KEY, device INTEGER, inode INTEGER, offset INTEGER)')
    c.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS alert_state (key TEXT PRIMARY KEY, active INTEGER, sent REAL)')
    c.execute('CREATE TABLE IF NOT EXISTS auth_events (id TEXT PRIMARY KEY, ts REAL, ip TEXT)')
    c.execute('CREATE INDEX IF NOT EXISTS auth_ts ON auth_events(ts)')
    c.execute('CREATE INDEX IF NOT EXISTS endlessh_ip ON endlessh_sessions(ip, started)')
    c.execute('CREATE INDEX IF NOT EXISTS events_ip ON events(ip, ts)')
    c.execute('CREATE TABLE IF NOT EXISTS http_details (event_id INTEGER PRIMARY KEY, user_agent TEXT, profile TEXT, scan_label TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS watch_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, kind TEXT, path TEXT, window_seconds INTEGER, threshold INTEGER, enabled INTEGER)')
    return c


def initialize_db():
    if CONFIG['capture_credentials']:
        with credentials_connect():
            pass
    with DB_LOCK:
        with db_connect() as c:
            n = c.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            if n == 0:
                for fn in (EVENTFILE + '.old', EVENTFILE):
                    try:
                        with open(fn, encoding='utf-8') as f:
                            for line in f:
                                try:
                                    e = json.loads(line)
                                    c.execute('INSERT INTO events VALUES (?,?,?,?)', (int(e['ts']), str(e.get('ip',''))[:48], str(e.get('path',''))[:150], str(e.get('method',''))[:16]))
                                except (ValueError, KeyError, TypeError):
                                    continue
                    except OSError:
                        pass
            c.execute("INSERT OR IGNORE INTO meta VALUES ('http_lifetime', ?)", (str(c.execute('SELECT COUNT(*) FROM events').fetchone()[0]),))
            c.execute("INSERT OR IGNORE INTO meta VALUES ('endlessh_lifetime', ?)", (str(c.execute('SELECT COUNT(*) FROM endlessh_sessions').fetchone()[0]),))


def total_events():
    try:
        with DB_LOCK:
            with db_connect() as c:
                return c.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    except sqlite3.Error:
        return len(EVENTS)


def full_timeline(hours=48):
    end = int(time.time()) // 3600 * 3600
    start = end - (hours-1)*3600
    bins = [0]*hours
    try:
        with DB_LOCK:
            with db_connect() as c:
                rows = c.execute('SELECT (ts / 3600) * 3600, count(*) FROM events WHERE ts >= ? GROUP BY (ts / 3600)', (start,)).fetchall()
        for epoch, n in rows:
            k = (epoch - start)//3600
            if 0 <= k < hours: bins[k] = n
    except sqlite3.Error:
        pass
    return [{'hour': time.strftime('%d.%m %H',time.localtime(start+i*3600)), 'events': n} for i,n in enumerate(bins)]


def webhooks_notify(content):
    if not os.path.isfile(WEBHOOK_FILE):
        return False
    try:
        with open(WEBHOOK_FILE, encoding='utf-8') as f:
            url = f.read().strip()
        if not url.startswith('https://discord.com/api/webhooks/') and not url.startswith('https://discordapp.com/api/webhooks/'):
            return
        body = json.dumps({'content': content[:1800], 'allowed_mentions': {'parse': []}}).encode()
        req = urllib.request.Request(url, body, {'Content-Type':'application/json','User-Agent':'FrogSOC/6.0'}, method='POST')
        with urllib.request.urlopen(req, timeout=6) as r:
            r.read(128)
        return True
    except (OSError, ValueError, urllib.error.URLError):
        logging.exception('Discord: wysyłka nieudana')
        return False


def alert_worker():
    while True:
        try:
            import_auth_logs()
            if CONFIG['alerts']['enabled']:
                dispatch_alerts(alert_candidates())
        except Exception:
            logging.exception('Worker alertów')
        time.sleep(CONFIG['alerts']['interval_seconds'])


def geo_lookup(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global: return
        safe_ip = str(addr)
    except ValueError:
        return
    try:
        with GEO_LOCK:
            with DB_LOCK:
                with db_connect() as c:
                    old = c.execute('SELECT checked FROM geo WHERE ip=?',(safe_ip,)).fetchone()
                    if old and time.time()-old[0] < GEO_REFRESH: return
            # Third party geo service receives the public attacker IP; not credentials.
            req = urllib.request.Request('https://ipwho.is/'+safe_ip, headers={'User-Agent':'FrogSOC/6.0'})
            with urllib.request.urlopen(req,timeout=3) as r:
                data = json.load(r)
            if not data.get('success'): return
            lat,lon=float(data['latitude']),float(data['longitude'])
            if not (-90<=lat<=90 and -180<=lon<=180): return
            with DB_LOCK:
                with db_connect() as c:
                    c.execute('INSERT OR REPLACE INTO geo VALUES (?,?,?,?,?)', (safe_ip,str(data.get('country','?'))[:80],lat,lon,int(time.time())))
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError, sqlite3.Error):
        pass


def geo_worker():
    # At most 12 requests per hour, one lookup every 5 minutes.
    while True:
        try:
            with DB_LOCK:
                with db_connect() as c:
                    ips = [x[0] for x in c.execute('SELECT ip FROM events GROUP BY ip ORDER BY MAX(ts) DESC LIMIT 35').fetchall()]
                    done = set(x[0] for x in c.execute('SELECT ip FROM geo WHERE checked >= ?', (int(time.time())-GEO_REFRESH,)).fetchall())
            for ip in ips:
                if ip not in done:
                    geo_lookup(ip)
                    break
        except Exception:
            pass
        time.sleep(300)


def geo_page():
    with DB_LOCK:
        with db_connect() as c:
            points = c.execute('SELECT country,lat,lon,ip FROM geo ORDER BY checked DESC LIMIT 80').fetchall()
    dots = []
    for country,lat,lon,ip in points:
        x=(lon+180)/360*960
        y=(90-lat)/180*440
        dots.append('<circle cx="'+str(round(x,1))+'" cy="'+str(round(y,1))+'" r="5" fill="#33ff99"><title>'+esc(country)+' — '+esc(ip)+'</title></circle>')
    grid = ''.join('<path d="M0 '+str(y)+' H960" stroke="#245248"/>' for y in range(40,440,40)) + ''.join('<path d="M'+str(x)+' 0 V440" stroke="#245248"/>' for x in range(0,960,80))
    return layout('🌍 Mapa IP · geo', '<section class="box"><p class="muted">Schematyczna mapa współrzędnych (bez konturów państw). IP są geolokalizowane orientacyjnie przez usługę ipwho.is; tylko adresy publiczne, maksymalnie 12 nowych IP/h. Geolokalizacja nie dowodzi pochodzenia ataku.</p><svg viewBox="0 0 960 440" role="img" aria-label="Współrzędne geograficzne IP" style="width:100%;background:#091923;border:1px solid #264c45">'+grid+''.join(dots)+'</svg><p>'+str(len(points))+' zlokalizowanych IP</p></section>')


def endlessh_record(line, reference=None):
    """Parse upstream Endlessh -v stdout or -v -s syslog (seconds are decimal)."""
    m = re.search(r'\b(ACCEPT|CLOSE) host=(\S+) port=(\d+) fd=(\d+)\b(.*)', line)
    if not m:
        return None
    # Shared syslog files must identify the emitting program.
    prefix = line[:m.start()]
    iso = re.search(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)', prefix)
    if iso:
        ts = datetime.datetime.fromisoformat(iso.group().replace('Z', '+00:00')).timestamp()
    else:
        stamp = re.match(r'^(?:<\d+>)?([A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d)', line)
        if not stamp or not re.search(r'\bendlessh(?:\[\d+\])?:', prefix):
            return None
        ref = datetime.datetime.fromtimestamp(reference if reference is not None else time.time())
        # RFC3164 has no year: choose the nearest year to the file's modification time.
        candidates = []
        for year in (ref.year-1, ref.year, ref.year+1):
            try:
                candidates.append(datetime.datetime.strptime(str(year)+' '+stamp[1], '%Y %b %d %H:%M:%S').timestamp())
            except ValueError:
                pass
        ts = min(candidates, key=lambda v: abs(v-ref.timestamp()))
    ip = str(ipaddress.ip_address(m[2]))
    port, fd = int(m[3]), int(m[4])
    if not 0 < port <= 65535:
        return None
    seconds = None
    if m[1] == 'CLOSE':
        d = re.search(r'\btime=(\d+(?:\.\d+)?)\b', m[5])
        if not d:
            return None
        seconds = float(d[1])
        if not math.isfinite(seconds):
            return None
    # Ignore syslog envelope so duplicated log destinations do not duplicate sessions.
    key = hashlib.sha256((str(ts)+' '+m.group()).encode()).hexdigest()
    return key, m[1], ip, port, fd, ts, seconds


def store_endlessh(c, record):
    key, kind, ip, port, fd, ts, seconds = record
    if not c.execute('INSERT OR IGNORE INTO endlessh_seen (id,ts) VALUES (?,?)', (key,ts)).rowcount:
        return
    if kind == 'ACCEPT':
        if c.execute('SELECT 1 FROM endlessh_sessions WHERE ip=? AND port=? AND fd=? AND ended IS NOT NULL AND ABS(started-?)<2 LIMIT 1', (ip,port,fd,ts)).fetchone():
            return
        c.execute('INSERT INTO endlessh_sessions VALUES (?,?,?,?,?,NULL,NULL)', (key, ip, port, fd, ts))
        meta_increment(c, 'endlessh_lifetime')
    else:
        # Pair by full peer tuple and nearest start; fd alone is reused by Endlessh.
        row = c.execute('SELECT id FROM endlessh_sessions WHERE ip=? AND port=? AND fd=? AND ended IS NULL AND started<=? AND ABS(started-?)<2 ORDER BY ABS(started-?) LIMIT 1',
                        (ip, port, fd, ts, ts-seconds, ts-seconds)).fetchone()
        if row:
            c.execute('UPDATE endlessh_sessions SET ended=?, seconds=? WHERE id=?', (ts, seconds, row[0]))
        else:
            # CLOSE is sufficient even when ACCEPT rotated away or logging began mid-session.
            c.execute('INSERT INTO endlessh_sessions VALUES (?,?,?,?,?,?,?)', (key, ip, port, fd, ts-seconds, ts, seconds))
            meta_increment(c, 'endlessh_lifetime')


def import_endlessh_logs():
    global ENDLESSH_ERROR, ENDLESSH_UPDATED, ENDLESSH_SUCCESS
    paths = {p for pattern in ENDLESSH_LOGS for p in glob.glob(pattern)
             if os.path.isfile(p) and not p.endswith(('.gz', '.xz', '.bz2'))}
    errors = []
    # Old rotations first; persistent inode cursors survive rename rotation and restarts.
    for path in sorted(paths, key=os.path.getmtime):
        try:
            with open(path, 'rb') as f:
                st = os.fstat(f.fileno())
                with DB_LOCK:
                    with db_connect() as c:
                        row = c.execute('SELECT MAX(offset) FROM endlessh_offsets WHERE device=? AND inode=?', (st.st_dev, st.st_ino)).fetchone()
                        offset = row[0] or 0
                        if offset > st.st_size:
                            offset = 0
                        f.seek(offset)
                        # Bound each pass; do not advance past a partial line.
                        for _ in range(10000):
                            pos = f.tell()
                            line = f.readline(65537)
                            if not line:
                                break
                            if len(line) == 65537:
                                while line and not line.endswith(b'\n'):
                                    line = f.readline(65537)
                                continue
                            if not line.endswith(b'\n'):
                                f.seek(pos)
                                break
                            try:
                                record = endlessh_record(line.decode('utf-8', 'replace'), st.st_mtime)
                                if record:
                                    store_endlessh(c, record)
                            except (ValueError, OverflowError):
                                pass
                        c.execute('INSERT OR REPLACE INTO endlessh_offsets VALUES (?,?,?,?)', (path, st.st_dev, st.st_ino, f.tell()))
        except (OSError, sqlite3.Error) as exc:
            errors.append(path+': '+str(exc))
    ENDLESSH_ERROR = '; '.join(errors) or ('' if paths else 'Nie znaleziono plików logów Endlessh/syslog.')
    ENDLESSH_UPDATED = time.time()
    if paths and not errors:
        ENDLESSH_SUCCESS = ENDLESSH_UPDATED


def endlessh_worker():
    global ENDLESSH_ERROR
    while True:
        try:
            import_endlessh_logs()
        except Exception as exc:
            ENDLESSH_ERROR = 'Błąd importu Endlessh: '+str(exc)
        time.sleep(CONFIG['import_interval'])


def history_page():
    series=full_timeline(48)
    maxi=max([x['events'] for x in series]+[1])
    rows=''.join('<tr><td>'+esc(x['hour'])+'</td><td><div style="height:10px;background:#00ffaa;width:'+str(round(100*x['events']/maxi))+'%"></div></td><td>'+str(x['events'])+'</td></tr>' for x in series)
    return layout('📈 Historia ataków', '<section class="box"><h2>Historia 48h</h2><p>Łącznie w SQLite: '+str(total_events())+' zdarzeń, retencja według config.json. Dotychczasowe pliki events.jsonl zostają nietknięte.</p><table>'+rows+'</table></section>')


def frog4():
    with DB_LOCK:
        with db_connect() as c:
            count = int(meta_get(c, 'http_lifetime', '0'))
            ssh_count = int(meta_get(c, 'endlessh_lifetime', '0'))
    xp=count*10+ssh_count*5
    level=1+int(math.sqrt(xp/100))
    stage='🥚 Kijanka' if level<3 else '🐸 Żaba' if level<10 else '👑 Król żab' if level<25 else '🐉 Cyberżaba'
    badges=[name for limit,name in [(1,'Pierwszy skan'),(10,'Bot magnet'),(100,'Wartownik'),(500,'Obrońca'),(1000,'Soc master'),(5000,'Legendarny płaz')] if count>=limit]
    if ssh_count >= 10: badges.append('Zaklinacz SSH')
    if ssh_count >= 100: badges.append('Cierpliwy łowca')
    return layout('🐸 Ewolucja', '<section class="box" style="text-align:center"><div style="font-size:84px">🐸</div><h2>'+esc(stage)+'</h2><div class="big">LEVEL '+str(level)+'</div><p>'+str(xp)+' XP · '+str(count)+' obserwacji HTTP · '+str(ssh_count)+' sesji Endlessh (liczniki trwałe)</p><h2>Odznaki</h2><p>'+esc(' 🏅 '.join(badges) or 'Brak')+'</p></section>')


def load_events():
    for fn in [EVENTFILE + '.old', EVENTFILE]:
        try:
            with open(fn, encoding='utf-8') as f:
                for line in f:
                    try:
                        e = json.loads(line)
                        if isinstance(e, dict) and isinstance(e.get('ts'), (int, float)):
                            EVENTS.append(e)
                    except (ValueError, TypeError):
                        pass
        except OSError:
            pass


def log_event(ip, path, method, user_agent='', profile=''):
    event = {'ts': int(time.time()), 'ip': ip, 'path': path[:150], 'method': method[:16]}
    with LOCK:
        EVENTS.append(event)
        try:
            if os.path.exists(EVENTFILE) and os.path.getsize(EVENTFILE) > 150000:
                os.replace(EVENTFILE, EVENTFILE + '.old')
            with open(EVENTFILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event) + '\n')
        except OSError:
            pass
    try:
        with DB_LOCK:
            with db_connect() as c:
                cursor = c.execute('INSERT INTO events VALUES (?,?,?,?)', (event['ts'], event['ip'], event['path'], event['method']))
                c.execute('INSERT OR REPLACE INTO http_details VALUES (?,?,?,?)', (cursor.lastrowid, clean_agent(user_agent), profile[:32], scan_classification(path)[0]))
                meta_increment(c, 'http_lifetime')
    except sqlite3.Error:
        pass


def trusted(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_loopback or any(a in ipaddress.ip_network(net) for net in CONFIG['trusted_networks'])
    except ValueError:
        return False


def read_password():
    try:
        with open(PASSWORD_FILE, encoding='utf-8') as f:
            return f.read().strip()
    except OSError:
        return ''


def command_output(args, timeout=1.5):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def memory():
    d = {}
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                k, v = line.split(':', 1)
                d[k] = int(v.strip().split()[0])
        total = d.get('MemTotal', 0) // 1024
        avail = d.get('MemAvailable', d.get('MemFree', 0)) // 1024
        return {'total': total, 'used': max(0, total - avail), 'free': avail}
    except (OSError, ValueError):
        return {'total': 0, 'used': 0, 'free': 0}


def uptime():
    try:
        with open('/proc/uptime') as f:
            return int(float(f.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return 0


def net_ports():
    # Read kernel TCP tables: no need to install iproute2/ss.
    listening, established = set(), collections.Counter()
    for filename in ['/proc/net/tcp', '/proc/net/tcp6']:
        try:
            with open(filename) as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    port = int(parts[1].split(':')[1], 16)
                    state = parts[3]
                    if state == '0A':
                        listening.add(port)
                    if state == '01':
                        established[port] += 1
        except (OSError, ValueError, IndexError):
            pass
    return listening, established


def proc_names():
    names = set()
    try:
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            try:
                with open('/proc/' + pid + '/comm') as f:
                    names.add(f.read().strip().lower())
                with open('/proc/' + pid + '/cmdline', 'rb') as f:
                    cmd = f.read(512).replace(b'\x00', b' ').decode('utf-8', 'replace').lower()
                    for marker in ('gatus', 'endlessh', 'tailscaled'):
                        if marker in cmd:
                            names.add(marker)
            except OSError:
                pass
    except OSError:
        pass
    return names


def snapshot():
    now = time.monotonic()
    with LOCK:
        if CACHE['data'] is not None and now - CACHE['at'] < 8:
            return CACHE['data']
    ports, established = net_ports()
    processes = proc_names()
    mem = memory()
    disk = shutil.disk_usage('/')
    try:
        load1 = round(os.getloadavg()[0], 2)
    except OSError:
        load1 = 0
    result = {
        'mem': mem,
        'disk': {'total': disk.total // (1024 * 1024), 'used': disk.used // (1024 * 1024)},
        'uptime': uptime(), 'load1': load1,
        'services': [
            {'name': 'Frog SOC', 'ok': PORT in ports, 'detail': 'HTTP :' + str(PORT)},
            {'name': 'Endlessh', 'ok': ENDLESSH_PORT in ports,
             'detail': 'Połączenia established na :'+str(ENDLESSH_PORT)+': ' + str(established[ENDLESSH_PORT])},
            {'name': 'Gatus', 'ok': 'gatus' in processes, 'detail': 'Wykrywanie procesu (nie health check)'},
            {'name': 'Tailscale', 'ok': 'tailscaled' in processes, 'detail': 'Wykrywanie procesu (nie status tunelu)'},
        ],
        'listen_ports': sorted(ports)[:40],
        'endlessh_connections': established[ENDLESSH_PORT],
    }
    with HEALTH_LOCK:
        checks = dict(HEALTH_STATE)
    for service in result['services']:
        check=checks.get(service['name'])
        if check and check['ok'] is not None:
            service.update(ok=check['ok'],detail=check['detail'])
    with LOCK:
        CACHE.update(at=now, data=result)
    return result



def process_top(limit=8):
    """RSS from /proc; no ps dependency, may count shared memory twice."""
    out = []
    try:
        pids = [p for p in os.listdir('/proc') if p.isdigit()]
    except OSError:
        return out
    for pid in pids[:2048]:
        try:
            with open('/proc/' + pid + '/status', encoding='utf-8') as f:
                fields = {}
                for line in f:
                    if line.startswith(('Name:', 'VmRSS:')):
                        k, v = line.split(':', 1)
                        fields[k] = v.strip()
            kb = int(fields.get('VmRSS', '0 kB').split()[0])
            if kb:
                out.append({'pid': int(pid), 'name': fields.get('Name', '?')[:50],
                            'rss_mib': round(kb / 1024, 1)})
        except (OSError, ValueError, IndexError):
            continue
    return sorted(out, key=lambda x: x['rss_mib'], reverse=True)[:limit]


def ssh_failures():
    """Best effort: read local auth logs; avoid logging usernames or passwords."""
    files = CONFIG['auth_logs']
    matching = []
    seen = set()
    for fn in files:
        try:
            if not os.path.isfile(fn):
                continue
            # Only last 256 KiB of each file; don't load massive logs into RAM.
            with open(fn, 'rb') as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - 262144))
                raw = f.read().decode('utf-8', 'replace')
            for line in raw.splitlines():
                low = line.lower()
                if ('sshd' not in low and 'dropbear' not in low) or not any(
                    x in low for x in ('failed password', 'invalid user', 'authentication failure', 'login attempt', 'bad password')
                ):
                    continue
                m = re.search(r'(?:from|rhost=)\s*([0-9a-fA-F:.]+)', line)
                if m:
                    ip = m.group(1)
                    try:
                        ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    matching.append(ip)
            seen.add(fn)
        except (OSError, UnicodeError):
            continue
    counts = collections.Counter(matching)
    return {'count': sum(counts.values()), 'top_ips': counts.most_common(10),
            'sources': sorted(seen), 'note': 'Próbka ostatnich 256 KiB na plik; brak logu nie oznacza braku ataków'}


def timeline():
    return full_timeline(24)


def threat_alerts(s=None):
    alerts = [('UWAGA', message) for _, message in alert_candidates(s)]
    return alerts or [('INFO', 'Brak przekroczonych progów heurystycznych')]


def investigations():
    s = snapshot()
    ssh = ssh_failures()
    ps = process_top()
    alerts = threat_alerts(s)
    series = timeline()
    maxv = max([x['events'] for x in series] + [1])
    bars = ''.join("<tr><td>" + esc(x['hour']) + "</td><td><div style='background:#237955;height:13px;width:" +
                   str(round(100 * x['events'] / maxv)) + "%'></div></td><td>" + str(x['events']) + '</td></tr>' for x in series)
    prows = ''.join('<tr><td>' + esc(x['name']) + '</td><td>' + str(x['pid']) + '</td><td>' +
                    str(x['rss_mib']) + ' MiB</td></tr>' for x in ps)
    sshrows = ''.join('<tr><td>' + esc(ip) + '</td><td>' + str(n) + '</td></tr>' for ip, n in ssh['top_ips'])
    arows = ''.join('<li><b>' + esc(level) + '</b> — ' + esc(msg) + '</li>' for level, msg in alerts)
    return layout('SOC 5.0 · Analiza zdarzeń',
        "<div class='grid'><section class='box'><h2>🚨 Alarmy heurystyczne</h2><ul>" + arows +
        "</ul></section><section class='box'><h2>🔑 Nieudane SSH</h2><div class='big'>" + str(ssh['count']) +
        "</div><p class='muted'>" + esc(ssh['note']) + '</p><p class="muted">Logi: ' +
        esc(', '.join(ssh['sources']) or 'nie znaleziono / brak dostępu') +
        '</p><table><tr><th>IP</th><th>Wpisy</th></tr>' + sshrows +
        "</table></section></div><div class='grid'><section class='box'><h2>📈 Żądania HTTP — ostatnie 24h</h2>" +
        '<p class="muted">Zdarzenia z bazy SQLite, z uwzględnieniem retencji.</p><table>' +
        bars + "</table></section><section class='box'><h2>🧠 Procesy o najwyższym RSS</h2>" +
        '<p class="muted">RSS uwzględnia pamięć współdzieloną; sumy procesów mogą przekraczać rzeczywiste użycie.</p>' +
        '<table><tr><th>Proces</th><th>PID</th><th>RAM</th></tr>' + prows +
        '</table></section></div>')

def esc(s):
    return html.escape(str(s), quote=True)


def duration(sec):
    sec = int(max(0, sec))
    return f'{sec // 86400}d {(sec % 86400) // 3600}h {(sec % 3600) // 60}m'


def layout(title, content):
    return ("<!doctype html><html lang='pl'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<script defer src='/assets/live.js'></script><script defer src='/assets/features.js'></script>"
        "<title>Frog SOC 6.0 — " + esc(title) + "</title><style>"
        ":root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#020d11;color:#c8ffe0;"
        "font:15px system-ui,sans-serif}main{max-width:1100px;margin:0 auto;padding:20px}"
        "h1{font-size:27px;margin:12px 0}h2{font-size:17px;margin:0 0 14px}"
        "a{color:#80f7bc}nav a{margin-right:19px}nav{padding:15px 0;border-bottom:1px solid #27433d}"
        ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(205px,1fr));gap:13px;margin:17px 0}"
        ".box{background:#0b1a20;border:1px solid #1f8269;border-radius:13px;padding:17px;overflow:auto}"
        ".big{font-size:26px;font-weight:700;color:#9af4ba}.muted{color:#a7c1bc}"
        ".ok{color:#8deda8}.bad{color:#ffa48c}table{width:100%;border-collapse:collapse;font-size:13px}"
        "td,th{padding:9px;border-bottom:1px solid #28403b;text-align:left;word-break:break-word}"
        "progress{width:100%;height:12px;accent-color:#80f7bc}code{color:#b9fad2}"
        "input,select,button{font:inherit;padding:9px;border-radius:6px;max-width:100%;background:#102c30;color:#dcffe9;border:1px solid #39665b}form{display:flex;flex-wrap:wrap;gap:10px;align-items:end}label{display:grid;gap:5px}nav{display:flex;flex-wrap:wrap;gap:8px}svg{max-width:100%}@media(max-width:600px){main{padding:10px}td,th{padding:7px}h1{font-size:22px}.grid{grid-template-columns:1fr}}"
        "</style><main><nav><b>🐸 FROG SOC 6.0</b> &nbsp; "
        "<a href='/soc'>Centrum</a><a href='/stats'>Ataki</a><a href='/frog'>Żaba</a>"
        "<a href='/investigate'>Analiza</a><a href='/history'>Historia</a><a href='/geo'>Mapa IP</a><a href='/ssh'>SSH</a><a href='/activity'>Aktywność</a><a href='/credentials'>Formularze pułapki</a><a href='/credential-stats'>Statystyki logowania</a><a href='/campaigns'>Wzorce botów</a><a href='/reports'>Raport dzienny</a><a href='/rules'>Reguły</a><a href='/healthchecks'>Sprawność usług</a><a href='/demo'>Demo</a><a href='/settings'>Stan i konfiguracja</a><a href='/soc/json'>JSON</a></nav><article id='live-content'><h1>" + esc(title) + '</h1>' + content +
        "</article><p class='muted' id='live-status'>Aktualizacja w tle · dostęp Tailscale/localhost + hasło</p>"
        "</main></html>")


def analytics():
    with LOCK:
        ev = list(EVENTS)
    counts = collections.Counter(str(e.get('ip', '?')) for e in ev)
    paths = collections.Counter(str(e.get('path', '?')) for e in ev)
    now = time.time()
    with DB_LOCK:
        with db_connect() as c:
            last_hour = c.execute('SELECT COUNT(*) FROM events WHERE ts BETWEEN ? AND ?', (now-3600, now)).fetchone()[0]
    return ev, counts, paths, last_hour


def center():
    s = snapshot()
    ev, ips, paths, last_hour = analytics()
    m = s['mem']; d = s['disk']
    mp = round(100 * m['used'] / max(1, m['total']))
    dp = round(100 * d['used'] / max(1, d['total']))
    alerts = []
    if mp >= CONFIG['alerts']['ram_percent']:
        alerts.append('RAM przekracza próg konfiguracji')
    if dp >= CONFIG['alerts']['disk_percent']:
        alerts.append('Dysk przekracza próg konfiguracji')
    for svc in s['services']:
        if not svc['ok'] and svc['name'] in CONFIG['required_services']:
            alerts.append(svc['name'] + ': niewykryta (sprawdź konfigurację)')
    blocks = [
        "<div class='box'><span class='muted'>RAM</span><div class='big'>" + str(m['used']) + ' / ' + str(m['total']) +
        " MiB</div><progress max='100' value='" + str(mp) + "'></progress></div>",
        "<div class='box'><span class='muted'>Dysk /</span><div class='big'>" + str(d['used']) + ' / ' + str(d['total']) +
        " MiB</div><progress max='100' value='" + str(dp) + "'></progress></div>",
        "<div class='box'><span class='muted'>Load (1 min)</span><div class='big'>" + str(s['load1']) +
        "</div><span class='muted'>Uptime: " + duration(s['uptime']) + '</span></div>',
        "<div class='box'><span class='muted'>Pułapka HTTP</span><div class='big'>" + str(len(ev)) +
        "</div><span class='muted'>Ostatnia godzina: " + str(last_hour) + '</span></div>',
    ]
    services = ''.join("<tr><td>" + esc(x['name']) + "</td><td class='" + ('ok' if x['ok'] else 'bad') + "'>" +
                       ('● Wykryta' if x['ok'] else '● Brak') + '</td><td>' + esc(x['detail']) + '</td></tr>'
                       for x in s['services'])
    alarms = ''.join('<li>' + esc(x) + '</li>' for x in alerts) or '<li>Brak alertów progowych.</li>'
    return layout('Centrum dowodzenia',
        traffic_chart() + "<section class='grid'>" + ''.join(blocks) + '</section>' +
        "<div class='grid'><section class='box'><h2>🛡️ Usługi</h2><table>" + services + '</table></section>' +
        "<section class='box'><h2>🚨 Alerty</h2><ul>" + alarms + '</ul></section></div>' +
        "<section class='box'><h2>Porty nasłuchujące na VPS</h2><p><code>" +
        esc(', '.join(map(str, s['listen_ports'])) or 'brak') + '</code></p>' +
        "<p class='muted'>Lokalne porty TCP, nie liczba publicznych portów przydzielonych przez hosting.</p></section>")


def stats():
    ev, ips, paths, last_hour = analytics()
    s = snapshot()
    rows = ''.join('<tr><td>' + esc(datetime.datetime.fromtimestamp(e['ts']).strftime('%Y-%m-%d %H:%M:%S')) +
                   '</td><td>' + esc(e.get('ip', '')) + '</td><td>' + esc(e.get('method', '')) +
                   '</td><td>' + esc(e.get('path', '')) + '</td></tr>' for e in reversed(ev[-45:]))
    rankings = ''.join('<tr><td>' + esc(ip) + '</td><td>' + str(num) + '</td></tr>' for ip, num in ips.most_common(10))
    popular = ''.join('<tr><td>' + esc(p) + '</td><td>' + str(num) + '</td></tr>' for p, num in paths.most_common(10))
    return layout('Statystyki pułapki',
        '<p>W pamięci maks. 600 zdarzeń, także odczytanych z poprzedniej wersji. ' +
        'Ostatnia godzina: <b>' + str(last_hour) + '</b>. Endlessh established: <b>' +
        str(s['endlessh_connections']) + '</b>.</p>' +
        "<div class='grid'><section class='box'><h2>Top IP</h2><table>" + rankings +
        "</table></section><section class='box'><h2>Top ścieżki</h2><table>" + popular +
        "</table></section></div><section class='box'><h2>Ostatnie żądania</h2><table>" +
        '<tr><th>Czas</th><th>IP</th><th>Metoda</th><th>Ścieżka</th></tr>' + rows + '</table></section>')


def frog():
    return frog4()

def old_frog():
    ev, _, _, _ = analytics()
    xp = len(ev) * 10
    level = xp // 100 + 1
    achievements = [label for needed, label in [(1, 'Pierwszy gość'), (10, '10 żądań'), (100, 'Sto żądań'),
                                                (500, 'Król żab')] if len(ev) >= needed]
    return layout('🐸 Frog Tamagotchi',
        "<div class='box' style='text-align:center'><div style='font-size:94px'>🐸</div>"
        "<div class='big'>Poziom " + str(level) + '</div><p>XP: ' + str(xp) +
        '</p><p>+10 XP za żądanie do pułapki · licznik dotyczy ostatnich 600 zapisanych zdarzeń</p>'
        '<h2>Osiągnięcia</h2><p>' + esc(' · '.join(achievements) or 'Jeszcze brak') + '</p></div>')


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'FrogSOC/6.0'
    def log_message(self, *args):
        pass

    def send(self, code, body, ctype='text/html; charset=utf-8', headers=None):
        b = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(b)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def authorized(self):
        if not trusted(self.client_address[0]):
            self.send(403, layout('Odmowa', '<p>Panel tylko przez Tailscale lub localhost.</p>'))
            return False
        auth = self.headers.get('Authorization', '')
        expected = 'Basic ' + base64.b64encode(('frog:' + read_password()).encode()).decode()
        if not read_password() or not secrets.compare_digest(auth, expected):
            self.send(401, 'Wymagane hasło panelu Frog SOC.', 'text/plain; charset=utf-8',
                      {'WWW-Authenticate': 'Basic realm="Frog SOC", charset="UTF-8"'})
            return False
        return True

    def do_GET(self):
        self.route()

    def do_POST(self):
        self.route()

    def capture_form(self, profile='router'):
        if not CONFIG['capture_credentials']:
            return True
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1:
            self.send(400, 'Wymagana długość formularza.', 'text/plain; charset=utf-8')
            return False
        try:
            length = int(self.headers['Content-Length'])
        except (ValueError, TypeError):
            self.send(400, 'Niepoprawna długość.', 'text/plain; charset=utf-8')
            return False
        if not 0 <= length <= 4096:
            self.send(413, 'Za duży formularz.', 'text/plain; charset=utf-8')
            return False
        if self.headers.get_content_type() != 'application/x-www-form-urlencoded':
            self.send(415, 'Nieobsługiwany formularz.', 'text/plain; charset=utf-8')
            return False
        old_timeout = self.connection.gettimeout()
        try:
            self.connection.settimeout(3)
            body = self.rfile.read(length)
            if len(body) != length:
                self.send(400, 'Niekompletny formularz.', 'text/plain; charset=utf-8')
                return False
            fields = parse_qs(body.decode('utf-8', 'replace'), keep_blank_values=True, max_num_fields=16)
        except (OSError, ValueError):
            self.send(400, 'Nie można odczytać formularza.', 'text/plain; charset=utf-8')
            return False
        finally:
            self.connection.settimeout(old_timeout)
        if 'username' in fields or 'password' in fields:
            try:
                save_credentials(self.client_address[0], fields.get('username', [''])[0], fields.get('password', [''])[0], profile)
            except (OSError, sqlite3.Error):
                logging.error('Nie udało się zapisać formularza honeypota')
                self.send(503, 'Spróbuj ponownie później.', 'text/plain; charset=utf-8')
                return False
        return True

    def delete_submissions(self):
        if self.command != 'POST':
            self.send(405, 'Wymagane POST.', 'text/plain; charset=utf-8', {'Allow': 'POST'})
            return
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1 or self.headers.get_content_type() != 'application/x-www-form-urlencoded':
            self.send(400, 'Nieprawidłowy formularz.', 'text/plain; charset=utf-8')
            return
        try:
            length = int(self.headers.get('Content-Length', '-1'))
            if not 0 <= length <= 16384:
                raise ValueError('Za duży formularz')
            old_timeout = self.connection.gettimeout()
            try:
                self.connection.settimeout(3)
                body = self.rfile.read(length)
            finally:
                self.connection.settimeout(old_timeout)
            if len(body) != length:
                raise ValueError('Niekompletny formularz')
            fields = parse_qs(body.decode('utf-8', 'strict'), keep_blank_values=True, max_num_fields=256)
            count = delete_credentials(fields)
        except PermissionError:
            self.send(403, 'Formularz wygasł lub token jest niepoprawny. Odśwież stronę.', 'text/plain; charset=utf-8')
            return
        except (OSError, ValueError, UnicodeError):
            self.send(400, 'Nieprawidłowe dane lub brak potwierdzenia USUN.', 'text/plain; charset=utf-8')
            return
        self.send(303, '', headers={'Location': '/credentials?deleted='+str(count)})

    def save_rule(self):
        if self.command!='POST':
            self.send(405,'Wymagane POST.','text/plain; charset=utf-8',{'Allow':'POST'})
            return
        try:
            if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length',[]))!=1 or self.headers.get_content_type()!='application/x-www-form-urlencoded':
                raise ValueError('Nieprawidłowy formularz')
            length=int(self.headers['Content-Length'])
            if not 0<=length<=16384: raise ValueError('Za duży formularz')
            old=self.connection.gettimeout()
            try:
                self.connection.settimeout(3);body=self.rfile.read(length)
            finally:
                self.connection.settimeout(old)
            if len(body)!=length: raise ValueError('Niekompletny formularz')
            fields=parse_qs(body.decode('utf-8','strict'),keep_blank_values=True,max_num_fields=32)
            change_rule(fields)
        except PermissionError:
            self.send(403,'Formularz wygasł. Odśwież stronę.','text/plain; charset=utf-8');return
        except (OSError,ValueError,UnicodeError) as exc:
            self.send(400,layout('Nieprawidłowa reguła','<p>'+esc(exc)+'</p>'));return
        self.send(303,'',headers={'Location':'/rules?saved=1'})

    def route(self):
        path = urlsplit(self.path).path
        if path in ('/assets/features.js','/assets/world.svg'):
            name='features.js' if path.endswith('.js') else 'world.svg'
            try:
                with open(os.path.join(ASSET_DIR,name),encoding='utf-8') as source:
                    self.send(200, source.read(), 'application/javascript; charset=utf-8' if name.endswith('.js') else 'image/svg+xml')
            except OSError:
                self.send(503, 'Brak zasobów aplikacji.', 'text/plain; charset=utf-8')
            return
        if path in ('/demo','/demo/data'):
            if not CONFIG['demo_enabled']:
                self.send(404, 'Demo wyłączone.', 'text/plain; charset=utf-8')
            elif path=='/demo/data':
                self.send(200,json.dumps(demo_data()),'application/json; charset=utf-8')
            else:
                self.send(200,demo_page())
            return
        if path in ('/soc', '/stats', '/frog', '/soc/json', '/investigate', '/geo', '/history', '/ssh', '/ssh.csv', '/ip', '/activity', '/settings', '/credentials', '/credentials/delete', '/credential-stats', '/campaigns', '/reports', '/rules', '/rules/save', '/healthchecks', '/geo/data', '/assets/live.js'):
            if not self.authorized():
                return
            params = {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}
            try:
                if path == '/rules/save':
                    self.save_rule()
                    return
                if path in ('/rules','/healthchecks'):
                    self.send(200, rules_page(params) if path=='/rules' else health_page())
                    return
                if path == '/geo/data':
                    self.send(200,json.dumps(map_data(params.get('day',''))),'application/json; charset=utf-8')
                    return
                if path == '/geo':
                    self.send(200,map_page(params.get('day','')))
                    return
                if path == '/credentials/delete':
                    self.delete_submissions()
                    return
                if path in ('/credential-stats', '/campaigns', '/reports'):
                    self.send(200, {'/credential-stats': credential_stats_page, '/campaigns': campaigns_page, '/reports': reports_page}[path]())
                    return
                if path == '/credentials':
                    self.send(200, credentials_page(params))
                    return
                if path == '/assets/live.js':
                    self.send(200, live_script(), 'application/javascript; charset=utf-8')
                    return
                if path == '/ssh.csv':
                    self.send(200, endlessh_csv(params), 'text/csv; charset=utf-8', {'Content-Disposition': 'attachment; filename="endlessh.csv"'})
                    return
                if path == '/ssh':
                    self.send(200, ssh_page(params=params))
                    return
                if path in ('/ip', '/activity', '/settings'):
                    self.send(200, {'/ip': lambda: ip_page(params.get('ip', '')), '/activity': lambda: activity_page(params), '/settings': settings_page}[path]())
                    return
            except ValueError as exc:
                self.send(400, layout('Nieprawidłowy filtr', '<p>'+esc(exc)+'</p>'))
                return
            if path == '/soc/json':
                s = snapshot().copy()
                ev, ips, paths, hour = analytics()
                s.update({'ssh_log_sample': ssh_failures(), 'http_timeline_24h': timeline(), 'top_processes': process_top(), 'alerts': threat_alerts(s), 'http_events_buffered': len(ev), 'http_events_last_hour': hour,
                          'top_ips': ips.most_common(10), 'top_paths': paths.most_common(10)})
                self.send(200, json.dumps(s, ensure_ascii=False), 'application/json; charset=utf-8')
            else:
                self.send(200, {'/soc': center, '/stats': stats, '/frog': frog, '/investigate': investigations, '/geo': geo_page, '/history': history_page, '/ssh': ssh_page}[path]())
            return
        if path == '/health':
            self.send(200, 'ok', 'text/plain; charset=utf-8')
            return
        profile = trap_profile(path)
        if self.command == 'POST' and profile:
            if not self.capture_form(profile):
                return
        log_event(self.client_address[0], path, self.command, self.headers.get('User-Agent',''), profile or '')
        if path=='/':
            self.send(200, trap_hub() if CONFIG['honeypots']['homepage']=='hub' else trap_page(CONFIG['honeypots']['homepage']))
        elif profile:
            self.send(200, trap_page(profile, failed=self.command=='POST'))
        elif path in ('/.env','/.git/config','/backup.zip','/config.json'):
            self.send(200, decoy_file(path), 'text/plain; charset=utf-8')
        else:
            self.send(404, '<!doctype html><title>404</title><h2>404 Not Found</h2>')



class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16
    allow_reuse_address = True
    def process_request(self, request, client_address):
        if not MAX_ACTIVE.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            MAX_ACTIVE.release()
            raise
    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            MAX_ACTIVE.release()


def meta_get(c, key, default=''):
    row = c.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
    return row[0] if row else default


def meta_set(c, key, value):
    c.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, str(value)))


def meta_increment(c, key):
    c.execute('INSERT INTO meta VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1', (key, '1'))


def canonical_ip(ip):
    addr = ipaddress.ip_address(ip)
    return str(addr.ipv4_mapped if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped else addr)


def ip_variants(ip):
    value = canonical_ip(ip)
    return [value, '::ffff:'+value] if ':' not in value else [value]


def ip_link(ip):
    return '<a href="/ip?'+esc(urlencode({'ip': canonical_ip(ip)}))+'">'+esc(ip)+'</a>'


def stamp(ts):
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if ts is not None else '—'


def session_filter(params):
    clauses, values = [], []
    if params.get('ip'):
        variants = ip_variants(params['ip'].strip())
        clauses.append('ip IN ('+','.join('?' for _ in variants)+')')
        values.extend(variants)
    dates = {}
    for key, op in (('from', '>='), ('to', '<')):
        if params.get(key):
            try:
                day = datetime.datetime.strptime(params[key], '%Y-%m-%d')
            except ValueError:
                raise ValueError('Data musi mieć format RRRR-MM-DD')
            dates[key] = day
            if key == 'to':
                day += datetime.timedelta(days=1)
            clauses.append('started '+op+' ?')
            values.append(day.timestamp())
    if dates.get('from') and dates.get('to') and dates['from'] > dates['to']:
        raise ValueError('Początek zakresu jest późniejszy niż koniec')
    status = params.get('status', '')
    if status not in ('', 'closed', 'pending'):
        raise ValueError('Nieznany status sesji')
    if status:
        clauses.append('ended IS '+('NOT NULL' if status == 'closed' else 'NULL'))
    if params.get('min_seconds'):
        try:
            seconds = float(params['min_seconds'])
        except ValueError:
            raise ValueError('Długość musi być liczbą')
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError('Długość musi być nieujemną liczbą')
        clauses.append('seconds>=?')
        values.append(seconds)
    sort = params.get('sort', 'newest')
    orders = {'newest': 'started DESC,id DESC', 'longest': 'seconds DESC,started DESC,id DESC'}
    if sort not in orders:
        raise ValueError('Nieznane sortowanie')
    return (' WHERE '+' AND '.join(clauses) if clauses else ''), values, orders[sort]


def session_rows(params, page=1, export=False):
    where, values, order = session_filter(params)
    with DB_LOCK:
        with db_connect() as c:
            total = c.execute('SELECT COUNT(*) FROM endlessh_sessions'+where, values).fetchone()[0]
            pages = max(1, (total+CONFIG['page_size']-1)//CONFIG['page_size'])
            page = min(max(1, page), pages)
            limit = CONFIG['retention']['endlessh_rows'] if export else CONFIG['page_size']
            rows = c.execute('SELECT ip,port,started,ended,seconds FROM endlessh_sessions'+where+' ORDER BY '+order+' LIMIT ? OFFSET ?', values+[limit, 0 if export else (page-1)*limit]).fetchall()
    return rows, total, page, pages


def endlessh_csv(params):
    rows, _, _, _ = session_rows(params, export=True)
    stream = io.StringIO(newline='')
    writer = csv.writer(stream)
    writer.writerow(['ip', 'client_port', 'started_server_time', 'ended_server_time', 'duration_seconds'])
    for ip, port, start, end, seconds in rows:
        writer.writerow([ip, port, stamp(start), stamp(end), '' if seconds is None else '%.3f' % seconds])
    return '\ufeff'+stream.getvalue()


def filter_form(params):
    def field(name, label, kind='text'):
        return '<label>'+label+'<input name="'+name+'" type="'+kind+'" value="'+esc(params.get(name, ''))+'"></label>'
    options = lambda name, choices: '<select name="'+name+'">'+''.join('<option value="'+v+'"'+(' selected' if params.get(name, '')==v else '')+'>'+label+'</option>' for v,label in choices)+'</select>'
    return '<form method="get" action="/ssh">'+field('ip','Adres IP')+field('from','Od','date')+field('to','Do','date')+field('min_seconds','Minimum sekund','number')+'<label>Status'+options('status',[('', 'Wszystkie'),('closed','Zakończone'),('pending','Bez CLOSE')])+'</label><label>Kolejność'+options('sort',[('newest','Najnowsze'),('longest','Najdłuższe')])+'</label><button>Filtruj</button><a href="/ssh">Wyczyść</a></form>'


def ssh_page(page=1, params=None):
    params = params or {}
    try:
        page = int(params.get('page', page))
    except (ValueError, TypeError):
        raise ValueError('Nieprawidłowy numer strony')
    rows, total, page, pages = session_rows(params, page)
    ports, established = net_ports()
    table = ''.join('<tr><td>'+ip_link(ip)+'</td><td>'+str(port)+'</td><td>'+stamp(start)+'</td><td>'+stamp(end)+'</td><td>'+('%.3f s' % seconds if seconds is not None else 'brak CLOSE')+'</td></tr>' for ip,port,start,end,seconds in rows)
    nav = ''
    for target, label in ((page-1,'← Nowsze'), (page+1,'Starsze →')):
        if 1 <= target <= pages:
            nav += '<a href="/ssh?'+esc(urlencode(dict(params, page=target)))+'">'+label+'</a> '
    nav += 'Strona '+str(page)+' / '+str(pages)
    status = '<p>Ostatni poprawny odczyt: '+stamp(ENDLESSH_SUCCESS or None)+' · interwał '+str(CONFIG['import_interval'])+' s</p>'
    if ENDLESSH_ERROR:
        status += '<p class="bad">'+esc(ENDLESSH_ERROR)+'</p>'
    if not total:
        status += '<p>Brak zapisanych połączeń dla tych filtrów. Sprawdź logowanie Endlessh (-v) i ścieżkę logu.</p>'
    with DB_LOCK:
        with db_connect() as c:
            top = c.execute('SELECT ip,COUNT(*),MAX(seconds),SUM(COALESCE(seconds,0)) FROM endlessh_sessions GROUP BY ip ORDER BY COUNT(*) DESC LIMIT 10').fetchall()
    ranking = ''.join('<tr><td>'+ip_link(ip)+'</td><td>'+str(n)+'</td><td>'+('%.3f s' % longest if longest is not None else '—')+'</td><td>%.3f s</td></tr>' % summed for ip,n,longest,summed in top)
    failures = ssh_failures()
    authrows = ''.join('<tr><td>'+ip_link(ip)+'</td><td>'+str(n)+'</td></tr>' for ip,n in failures['top_ips'])
    return layout('🪤 SSH / Endlessh', '<section class="box"><h2>Historia Endlessh · port '+str(ENDLESSH_PORT)+'</h2><p>Nasłuch: '+('TAK' if ENDLESSH_PORT in ports else 'NIE')+' · aktywne TCP: '+str(established[ENDLESSH_PORT])+' · pasujące sesje: '+str(total)+'</p>'+filter_form(params)+status+'<p><a href="/ssh.csv?'+esc(urlencode({k:v for k,v in params.items() if k!='page'}))+'">Eksport CSV z filtrami</a></p><p class="muted">Czas w strefie serwera. Brak CLOSE: połączenie otwarte lub niekompletne logi. Retencja: '+str(CONFIG['retention']['endlessh_days'])+' dni / '+str(CONFIG['retention']['endlessh_rows'])+' sesji.</p><table><tr><th>IP</th><th>Port źródłowy</th><th>Początek</th><th>Koniec</th><th>Długość</th></tr>'+ (table or '<tr><td colspan="5">Brak danych</td></tr>')+'</table><p>'+nav+'</p></section><section class="box"><h2>Powracające IP · zachowana historia</h2><table><tr><th>IP</th><th>Sesje</th><th>Najdłuższa</th><th>Łącznie</th></tr>'+ranking+'</table></section><section class="box"><h2>Nieudane logowania sshd / Dropbear</h2><p>Osobna próbka logów: '+str(failures['count'])+'</p><table>'+authrows+'</table></section>')


def ip_page(ip):
    variants = ip_variants(ip)
    placeholders = ','.join('?' for _ in variants)
    with DB_LOCK:
        with db_connect() as c:
            summary = c.execute('SELECT COUNT(*),MIN(started),MAX(started),SUM(COALESCE(seconds,0)),MAX(seconds) FROM endlessh_sessions WHERE ip IN ('+placeholders+')', variants).fetchone()
            http = c.execute('SELECT COUNT(*),MIN(ts),MAX(ts) FROM events WHERE ip IN ('+placeholders+')',variants).fetchone()
            auth = c.execute('SELECT COUNT(*) FROM auth_events WHERE ip IN ('+placeholders+')',variants).fetchone()[0]
    count, first, last, seconds, longest = summary
    return layout('Adres IP · '+canonical_ip(ip), bot_profile(ip)+ '<section class="box"><p>Sesje Endlessh: <b>'+str(count)+'</b> · HTTP: <b>'+str(http[0])+'</b> · błędy SSH: <b>'+str(auth)+'</b></p><p>Pierwsza sesja: '+stamp(first)+' · ostatnia: '+stamp(last)+'</p><p>Łączny czas zakończonych sesji: %.3f s · najdłuższa: %.3f s</p>' % (seconds or 0,longest or 0)+'<a href="/ssh?'+esc(urlencode({'ip':canonical_ip(ip)}))+'">Wszystkie zachowane sesje tego IP</a> · <a href="/activity?'+esc(urlencode({'ip':canonical_ip(ip)}))+'">Wspólna oś aktywności IP</a><p class="muted">Podsumowanie dotyczy danych dostępnych w okresie retencji.</p></section>')


def import_auth_logs():
    global AUTH_ERROR
    errors = []
    for path in CONFIG['auth_logs']:
        try:
            if not os.path.exists(path):
                continue
            with open(path,'rb') as f:
                st=os.fstat(f.fileno())
                f.seek(max(0,st.st_size-262144))
                if st.st_size>262144:
                    f.readline()
                lines=f.read().decode('utf-8','replace').splitlines()
            with DB_LOCK:
                with db_connect() as c:
                    for line in lines:
                        if not re.search(r'\b(sshd|dropbear)(?:\[\d+\])?:',line) or not any(x in line.lower() for x in ('failed password','invalid user','authentication failure','login attempt','bad password')):
                            continue
                        m=re.search(r'(?:from\s+|rhost=)([0-9a-fA-F:.]+)',line)
                        if not m:
                            continue
                        try:
                            ip=canonical_ip(m[1])
                            # Reuse the timestamp parser for ISO / RFC3164 without persisting usernames.
                            prefix=re.sub(r'\b(?:sshd|dropbear)(?:\[\d+\])?:.*', 'endlessh: ', line)
                            record=endlessh_record(prefix+'ACCEPT host='+ip+' port=1 fd=0',st.st_mtime)
                            if record:
                                key=hashlib.sha256((str(record[5])+line).encode()).hexdigest()
                                c.execute('INSERT OR IGNORE INTO auth_events VALUES (?,?,?)',(key,record[5],ip))
                        except (ValueError,OverflowError):
                            continue
        except (OSError,sqlite3.Error) as exc:
            errors.append(path+': '+str(exc))
    AUTH_ERROR='; '.join(errors)


def activity_page(params=None):
    params=params or {}
    values=[]
    where=''
    if params.get('ip'):
        variants=ip_variants(params['ip'])
        where=' WHERE ip IN ('+','.join('?' for _ in variants)+')'
        values=variants
    with DB_LOCK:
        with db_connect() as c:
            rows=c.execute("SELECT * FROM (SELECT ts,ip,'HTTP' AS kind,method||' '||path AS detail FROM events"+where+" UNION ALL SELECT started,ip,'Endlessh',CASE WHEN seconds IS NULL THEN 'brak CLOSE' ELSE printf('%.3f s',seconds) END FROM endlessh_sessions"+where+" UNION ALL SELECT ts,ip,'SSH auth','Nieudana próba logowania' FROM auth_events"+where+") ORDER BY 1 DESC LIMIT 200",values*3).fetchall()
    body=''.join('<tr><td>'+stamp(ts)+'</td><td>'+ip_link(ip)+'</td><td>'+esc(kind)+'</td><td>'+esc(detail)+'</td></tr>' for ts,ip,kind,detail in rows)
    return layout('Wspólna aktywność', '<section class="box"><p>200 najnowszych zdarzeń HTTP, Endlessh i sshd/Dropbear. '+('Filtr IP: '+esc(params['ip']) if params.get('ip') else '')+'</p><table><tr><th>Czas</th><th>IP</th><th>Źródło</th><th>Zdarzenie</th></tr>'+body+'</table></section>')


def alert_candidates(s=None):
    s=s or snapshot()
    thresholds=CONFIG['alerts']
    now=time.time()
    result=[]
    for key,metric,threshold in (('ram',s['mem']['used']*100/max(s['mem']['total'],1),thresholds['ram_percent']),('disk',s['disk']['used']*100/max(s['disk']['total'],1),thresholds['disk_percent'])):
        if metric>=threshold:
            result.append((key, key.upper()+': '+str(round(metric))+'% (próg '+str(threshold)+'%)'))
    for service in s['services']:
        if service['name'] in CONFIG['required_services'] and not service['ok']:
            result.append(('service:'+service['name'],service['name']+': usługa niewykryta'))
    with DB_LOCK:
        with db_connect() as c:
            hour=c.execute('SELECT COUNT(*) FROM events WHERE ts BETWEEN ? AND ?',(now-3600,now)).fetchone()[0]
            previous=c.execute('SELECT COUNT(*) FROM events WHERE ts>=? AND ts<?',(now-7200,now-3600)).fetchone()[0]
            ips=c.execute('SELECT ip,COUNT(*) FROM events WHERE ts BETWEEN ? AND ? GROUP BY ip HAVING COUNT(*)>=? ORDER BY COUNT(*) DESC LIMIT 5',(now-3600,now,thresholds['ip_hour'])).fetchall()
            ssh=c.execute('SELECT COUNT(*) FROM auth_events WHERE ts BETWEEN ? AND ?',(now-3600,now)).fetchone()[0]
            longest=c.execute('SELECT MAX(seconds) FROM endlessh_sessions').fetchone()[0] or 0
            record=float(meta_get(c,'endlessh_record_notified','0'))
    if hour>=thresholds['http_hour']:
        result.append(('http:hour',str(hour)+' żądań HTTP / godzinę'))
    if hour>=thresholds['http_hour'] and hour>=max(previous,1)*thresholds['burst_factor']:
        result.append(('http:burst','Nagły wzrost HTTP: '+str(hour)+' wobec '+str(previous)+' w poprzedniej godzinie'))
    result.extend(('ip:'+canonical_ip(ip),'IP '+ip+': '+str(count)+' żądań / godzinę') for ip,count in ips)
    if ssh>=thresholds['ssh_hour']:
        result.append(('ssh:hour',str(ssh)+' nieudanych logowań SSH / godzinę'))
    if longest>=thresholds['endlessh_record_seconds'] and longest>record:
        result.append(('endlessh:record','Nowy rekord sesji Endlessh: %.3f s' % longest))
    if ENDLESSH_ERROR:
        result.append(('import:endlessh','Błąd odczytu logów Endlessh: '+ENDLESSH_ERROR))
    if MAINTENANCE_ERROR:
        result.append(('maintenance','Błąd utrzymania / backupu: '+MAINTENANCE_ERROR))
    result.extend(rule_alerts(now))
    return result


def dispatch_alerts(alerts, now=None):
    now=time.time() if now is None else now
    current=dict(alerts)
    with DB_LOCK:
        with db_connect() as c:
            prior={key:(active,sent) for key,active,sent in c.execute('SELECT key,active,sent FROM alert_state')}
    for key,message in current.items():
        active,sent=prior.get(key,(0,0))
        if not active or now-sent>=CONFIG['alerts']['cooldown_seconds']:
            if webhooks_notify('🚨 **FROG SOC 6.0** | '+message):
                with DB_LOCK:
                    with db_connect() as c:
                        c.execute('INSERT OR REPLACE INTO alert_state VALUES (?,?,?)',(key,1,now))
                        if key=='endlessh:record':
                            meta_set(c,'endlessh_record_notified',c.execute('SELECT COALESCE(MAX(seconds),0) FROM endlessh_sessions').fetchone()[0])
    for key,(active,sent) in prior.items():
        if active and key not in current:
            # Record notices are one-shot observations, not incidents requiring recovery.
            if key=='endlessh:record' or not CONFIG['alerts']['recovery'] or webhooks_notify('✅ **FROG SOC 6.0** | Ustąpił alert: '+key):
                with DB_LOCK:
                    with db_connect() as c:
                        c.execute('UPDATE alert_state SET active=0 WHERE key=?',(key,))


def maintenance_once(now=None):
    now=time.time() if now is None else now
    retention=CONFIG['retention']
    if os.path.exists(CREDENTIALS_DB):
        with DB_LOCK:
            with credentials_connect() as c:
                prune_credentials(c, now)
    with DB_LOCK:
        with db_connect() as c:
            for table,column,days,limit in (('events','ts',retention['http_days'],retention['http_rows']),('endlessh_sessions','started',retention['endlessh_days'],retention['endlessh_rows']),('auth_events','ts',retention['auth_days'],None)):
                c.execute('DELETE FROM '+table+' WHERE '+column+'<?',(now-days*86400,))
                if limit:
                    c.execute('DELETE FROM '+table+' WHERE rowid IN (SELECT rowid FROM '+table+' ORDER BY '+column+' DESC LIMIT -1 OFFSET ?)',(limit,))
            c.execute('DELETE FROM http_details WHERE event_id NOT IN (SELECT rowid FROM events)')
            # Drop old dedup keys only when all source files are consumed; cursor prevents replay.
            c.execute('DELETE FROM endlessh_seen WHERE ts<?',(now-retention['endlessh_days']*86400,))
            c.execute('DELETE FROM geo WHERE checked<?',(now-90*86400,))
            c.execute('DELETE FROM alert_state WHERE active=0 AND sent<?',(now-30*86400,))
            backup_due=now-float(meta_get(c,'last_backup','0'))>=CONFIG['maintenance']['backup_hours']*3600
    if backup_due:
        directory=ROOT+'/backups/automatic'
        os.makedirs(directory,mode=0o700,exist_ok=True)
        filename=directory+'/soc-'+time.strftime('%Y%m%d-%H%M%S',time.localtime(now))+'.sqlite3'
        temp=filename+'.tmp'
        try:
            with DB_LOCK:
                with db_connect() as src:
                    dst=sqlite3.connect(temp)
                    try:
                        src.backup(dst)
                    finally:
                        dst.close()
            os.chmod(temp,0o600)
            os.replace(temp,filename)
        finally:
            if os.path.exists(temp): os.unlink(temp)
        with DB_LOCK:
            with db_connect() as c:
                meta_set(c,'last_backup',now)
        backups=sorted(glob.glob(directory+'/soc-*.sqlite3'),reverse=True)
        for old in backups[CONFIG['maintenance']['backup_keep']:]:
            os.unlink(old)
    with DB_LOCK:
        with db_connect() as c:
            meta_set(c,'last_maintenance',now)
            c.execute('PRAGMA incremental_vacuum(100)')


def maintenance_worker():
    global MAINTENANCE_ERROR
    while True:
        try:
            maintenance_once()
            MAINTENANCE_ERROR=''
        except Exception as exc:
            MAINTENANCE_ERROR=str(exc)
            logging.exception('Utrzymanie')
        time.sleep(CONFIG['maintenance']['interval_seconds'])


def settings_page():
    with DB_LOCK:
        with db_connect() as c:
            backup=meta_get(c,'last_backup','0')
            maintenance=meta_get(c,'last_maintenance','0')
    return layout('Stan i konfiguracja', '<section class="box"><p>Wersja '+VERSION+' · konfiguracja: '+esc(CONFIG_PATH)+'</p><p>Port Frog: '+str(PORT)+' · port Endlessh: '+str(ENDLESSH_PORT)+'</p><p>Poprawny odczyt Endlessh: '+stamp(ENDLESSH_SUCCESS or None)+'</p><p>Backup SQLite: '+stamp(float(backup) or None)+' · utrzymanie: '+stamp(float(maintenance) or None)+'</p><p class="bad">'+esc(ENDLESSH_ERROR or MAINTENANCE_ERROR or AUTH_ERROR)+'</p><p>Zmiany pliku wymagają restartu Frog SOC. Konfiguracja nie przestawia usługi Endlessh ani reguł NAT/firewall.</p><pre>'+esc(json.dumps(CONFIG,ensure_ascii=False,indent=2))+'</pre></section>')


def live_script():
    return """(() => {
const interval = INTERVAL;
let busy = false;
setInterval(async () => {
  if (document.getElementById('world-map') || location.pathname==='/rules') return;
  if (busy || document.hidden || document.activeElement?.closest('form')) return;
  if (document.querySelector('form[data-dirty]')) return;
  busy = true;
  const status = document.getElementById('live-status');
  try {
    const response = await fetch(location.href, {cache: 'no-store', credentials: 'same-origin'});
    if (!response.ok) throw new Error(String(response.status));
    const doc = new DOMParser().parseFromString(await response.text(), 'text/html');
    const next = doc.getElementById('live-content');
    if (next) document.getElementById('live-content').replaceChildren(...next.childNodes);
    if (status) status.textContent = 'Zaktualizowano: ' + new Date().toLocaleTimeString();
  } catch (_) { if (status) status.textContent = 'Brak aktualizacji — sprawdź połączenie'; }
  finally { busy = false; }
}, interval);
document.addEventListener('input', event => { const form = event.target.closest('form'); if(form) form.dataset.dirty='1'; });
})();""".replace('INTERVAL',str(CONFIG['refresh_seconds']*1000))


def traffic_chart():
    now=int(time.time())//3600*3600
    start=now-23*3600
    with DB_LOCK:
        with db_connect() as c:
            http=dict(c.execute('SELECT CAST(ts/3600 AS INT)*3600,COUNT(*) FROM events WHERE ts>=? GROUP BY 1',(start,)))
            ssh=dict(c.execute('SELECT CAST(started/3600 AS INT)*3600,COUNT(*) FROM endlessh_sessions WHERE started>=? GROUP BY 1',(start,)))
    maximum=max(list(http.values())+list(ssh.values())+[1])
    bars=[]
    for i in range(24):
        ts=start+i*3600
        for offset,series,color,name in ((0,http,'#7af7b7','HTTP'),(9,ssh,'#7db9ff','Endlessh')):
            value=series.get(ts,0)
            height=130*value/maximum
            bars.append('<rect x="'+str(12+i*24+offset)+'" y="'+str(150-height)+'" width="8" height="'+str(height)+'" fill="'+color+'"><title>'+esc(time.strftime('%d.%m %H:00',time.localtime(ts)))+' '+name+': '+str(value)+'</title></rect>')
    return '<section class="box"><h2>Aktywność · 24 godziny</h2><p>Zielony: HTTP · niebieski: sesje Endlessh. Dane z SQLite.</p><svg role="img" aria-label="Godzinowa aktywność HTTP i Endlessh z ostatnich 24 godzin" viewBox="0 0 600 175">'+''.join(bars)+'<text x="12" y="170" fill="#c8ffe0">−23h</text><text x="530" y="170" fill="#c8ffe0">teraz</text></svg></section>'


def credentials_connect():
    c = sqlite3.connect(CREDENTIALS_DB, timeout=3, factory=SOCConnection)
    os.chmod(CREDENTIALS_DB, 0o600)
    c.execute('PRAGMA secure_delete=ON')
    c.create_function('norm_ip', 1, canonical_ip)
    c.execute('CREATE TABLE IF NOT EXISTS submissions (id INTEGER PRIMARY KEY, ts REAL, ip TEXT, username TEXT, password TEXT)')
    c.execute('CREATE INDEX IF NOT EXISTS submissions_ts ON submissions(ts)')
    if 'profile' not in {row[1] for row in c.execute('PRAGMA table_info(submissions)')}:
        c.execute("ALTER TABLE submissions ADD COLUMN profile TEXT NOT NULL DEFAULT 'router'")
    return c


def prune_credentials(c, now):
    retention = CONFIG['retention']
    c.execute('DELETE FROM submissions WHERE ts<?', (now-retention['credentials_days']*86400,))
    c.execute('DELETE FROM submissions WHERE id IN (SELECT id FROM submissions ORDER BY ts DESC,id DESC LIMIT -1 OFFSET ?)', (retention['credentials_rows'],))


def save_credentials(ip, username, password, profile='router'):
    with DB_LOCK:
        with credentials_connect() as c:
            c.execute('INSERT INTO submissions (ts,ip,username,password,profile) VALUES (?,?,?,?,?)', (time.time(),ip,username[:256],password[:512],profile[:32]))
            prune_credentials(c, time.time())


def credentials_page(params=None):
    params = params or {}
    try:
        page = max(1, int(params.get('page', '1')))
    except ValueError:
        raise ValueError('Nieprawidłowy numer strony')
    if not os.path.exists(CREDENTIALS_DB):
        return layout('Formularze pułapki', '<section class="box"><p>Brak zapisanych formularzy. Zbieranie: '+('włączone' if CONFIG['capture_credentials'] else 'wyłączone')+'</p></section>')
    with DB_LOCK:
        with credentials_connect() as c:
            total = c.execute('SELECT COUNT(*) FROM submissions').fetchone()[0]
            pages = max(1, (total+CONFIG['page_size']-1)//CONFIG['page_size'])
            page = min(page, pages)
            rows = c.execute('SELECT id,ts,ip,username,password,profile FROM submissions ORDER BY ts DESC,id DESC LIMIT ? OFFSET ?', (CONFIG['page_size'],(page-1)*CONFIG['page_size'])).fetchall()
            max_id = c.execute('SELECT COALESCE(MAX(id),0) FROM submissions').fetchone()[0]
    token = deletion_token(max_id)
    body = ''.join('<tr><td><input type="checkbox" name="id" value="'+str(row_id)+'" aria-label="Zaznacz wpis '+str(row_id)+'"></td><td>'+stamp(ts)+'</td><td>'+ip_link(ip)+'</td><td>'+esc(profile)+'</td><td><code>'+esc(username)+'</code></td><td><details><summary>Pokaż hasło</summary><code>'+esc(password)+'</code></details></td></tr>' for row_id,ts,ip,username,password,profile in rows)
    nav = 'Strona '+str(page)+' / '+str(pages)
    if page>1: nav += ' <a href="/credentials?page='+str(page-1)+'">← Nowsze</a>'
    if page<pages: nav += ' <a href="/credentials?page='+str(page+1)+'">Starsze →</a>'
    message = '<p class="ok">Usunięto wpisów: '+str(int(params['deleted']))+'</p>' if params.get('deleted', '').isdigit() else ''
    return layout('Formularze pułapki', '<section class="box">'+message+'<p>Zbieranie: <b>'+('włączone' if CONFIG['capture_credentials'] else 'wyłączone')+'</b> · wpisy: '+str(total)+'</p><p>Loginy i hasła z fałszywego panelu routera. Retencja: '+str(CONFIG['retention']['credentials_days'])+' dni, maks. '+str(CONFIG['retention']['credentials_rows'])+' wpisów. Osobna baza jest dostępna tylko właścicielowi; nie jest objęta automatycznymi backupami telemetrii.</p><form method="post" action="/credentials/delete"><input type="hidden" name="token" value="'+esc(token)+'"><table><tr><th>Wybór</th><th>Czas</th><th>IP</th><th>Pułapka</th><th>Login</th><th>Hasło</th></tr>'+ (body or '<tr><td colspan="6">Brak formularzy</td></tr>')+'</table><label>Potwierdź usunięcie: wpisz USUN<input name="confirm" autocomplete="off"></label><button name="action" value="selected">Usuń zaznaczone</button><button name="action" value="all">Usuń całą historię z chwili otwarcia formularza</button></form><p>Nowe wpisy przechwycone po otwarciu formularza nie zostaną usunięte. Token ważny 30 minut.</p><p>'+nav+'</p></section>')


def deletion_token(max_id, now=None):
    payload = {'scope': 'credentials-delete', 'max_id': int(max_id), 'issued': time.time() if now is None else now}
    encoded = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).decode()
    signature = hmac.new(CSRF_KEY, encoded.encode(), hashlib.sha256).hexdigest()
    return encoded+'.'+signature


def validate_deletion_token(token, now=None):
    now = time.time() if now is None else now
    try:
        encoded, signature = token.split('.')
        expected = hmac.new(CSRF_KEY,encoded.encode(),hashlib.sha256).hexdigest()
        if not secrets.compare_digest(signature,expected):
            raise ValueError('signature')
        payload = json.loads(base64.urlsafe_b64decode(encoded))
        if payload['scope'] != 'credentials-delete' or type(payload['max_id']) is not int or payload['max_id']<0:
            raise ValueError('scope')
        issued = float(payload['issued'])
        if not math.isfinite(issued) or not -30 <= now-issued <= 1800:
            raise ValueError('expired')
        return payload['max_id'], issued
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise PermissionError('Niepoprawny token') from None


def delete_credentials(fields):
    def one(name):
        values = fields.get(name, [])
        if len(values)!=1:
            raise ValueError(name)
        return values[0]
    max_id, issued = validate_deletion_token(one('token'))
    if one('confirm') != 'USUN':
        raise ValueError('confirm')
    action = one('action')
    if action not in ('selected','all'):
        raise ValueError('action')
    ids = fields.get('id', [])
    if action=='selected':
        if not ids or len(ids)>200:
            raise ValueError('ids')
        ids = [int(value) for value in ids]
        if any(value<1 for value in ids):
            raise ValueError('ids')
    with DB_LOCK:
        with credentials_connect() as c:
            sql='DELETE FROM submissions WHERE id<=? AND ts<=?'
            params=[max_id,issued]
            if action=='selected':
                sql+=' AND id IN ('+','.join('?' for _ in ids)+')'
                params.extend(ids)
            return c.execute(sql,params).rowcount


def credential_statistics():
    with DB_LOCK:
        with credentials_connect() as c:
            total, ips, users, passwords = c.execute('SELECT COUNT(*),COUNT(DISTINCT norm_ip(ip)),COUNT(DISTINCT username),COUNT(DISTINCT password) FROM submissions').fetchone()
            usernames=c.execute('SELECT username,COUNT(*) FROM submissions GROUP BY username ORDER BY COUNT(*) DESC,username LIMIT 20').fetchall()
            secrets_rows=c.execute('SELECT password,COUNT(*) FROM submissions GROUP BY password ORDER BY COUNT(*) DESC,password LIMIT 20').fetchall()
            pairs=c.execute('SELECT username,password,COUNT(*),COUNT(DISTINCT norm_ip(ip)) FROM submissions GROUP BY username,password ORDER BY COUNT(*) DESC,username,password LIMIT 20').fetchall()
    return {'total':total,'ips':ips,'users':users,'passwords':passwords,'usernames':usernames,'secrets':secrets_rows,'pairs':pairs}


def credential_stats_page():
    data=credential_statistics()
    value=lambda text: esc(text) if text else '(pusty)'
    users=''.join('<tr><td>'+value(user)+'</td><td>'+str(n)+'</td></tr>' for user,n in data['usernames'])
    passwords=''.join('<tr><td><details><summary>Pokaż hasło</summary><code>'+value(password)+'</code></details></td><td>'+str(n)+'</td></tr>' for password,n in data['secrets'])
    pairs=''.join('<tr><td>'+value(user)+'</td><td><details><summary>Pokaż hasło</summary><code>'+value(password)+'</code></details></td><td>'+str(n)+'</td><td>'+str(ips)+'</td></tr>' for user,password,n,ips in data['pairs'])
    return layout('Statystyki prób logowania', '<section class="box"><p>Wpisy: '+str(data['total'])+' · IP: '+str(data['ips'])+' · różne loginy: '+str(data['users'])+' · różne hasła: '+str(data['passwords'])+'</p><p>Wyłącznie zachowane formularze honeypota, zgodnie z retencją. Hasła nie są wysyłane na Discord.</p></section><div class="grid"><section class="box"><h2>Popularne loginy · top 20</h2><table>'+users+'</table></section><section class="box"><h2>Popularne hasła · top 20</h2><table>'+passwords+'</table></section></div><section class="box"><h2>Powtarzające się kombinacje · top 20</h2><table><tr><th>Login</th><th>Hasło</th><th>Próby</th><th>IP</th></tr>'+pairs+'</table></section>')


def path_family(path):
    path=path.lower()
    if re.search(r'/(?:wp-|wordpress)',path):
        return 'WordPress'
    if path.startswith('/cgi-bin/'):
        return 'CGI / router'
    if path in ('/login','/admin','/login/','/admin/'):
        return 'Panel logowania'
    return re.sub(r'(?<=/)\d+(?=/|$)', ':id', path)[:150]


def campaign_patterns(now=None):
    now=time.time() if now is None else now
    config=CONFIG['campaigns']
    cutoff=now-config['window_hours']*3600
    with DB_LOCK:
        with credentials_connect() as c:
            pairs=c.execute('SELECT username,password,COUNT(*),COUNT(DISTINCT norm_ip(ip)),MIN(ts),MAX(ts) FROM submissions WHERE ts BETWEEN ? AND ? GROUP BY username,password HAVING COUNT(*)>=? AND COUNT(DISTINCT norm_ip(ip))>=? ORDER BY COUNT(*) DESC,username,password LIMIT 20',(cutoff,now,config['min_attempts'],config['min_ips'])).fetchall()
            credentials=[]
            for user,password,count,ips,first,last in pairs:
                peers=c.execute('SELECT DISTINCT norm_ip(ip) FROM submissions WHERE username=? AND password=? AND ts BETWEEN ? AND ? ORDER BY 1 LIMIT 20',(user,password,cutoff,now)).fetchall()
                credentials.append({'username':user,'password':password,'count':count,'ips':ips,'first':first,'last':last,'peers':[row[0] for row in peers]})
        with db_connect() as c:
            c.create_function('path_family',1,path_family)
            c.create_function('norm_ip',1,canonical_ip)
            groups=c.execute('SELECT path_family(path),COUNT(*),COUNT(DISTINCT norm_ip(ip)),MIN(ts),MAX(ts) FROM events WHERE ts BETWEEN ? AND ? GROUP BY path_family(path) HAVING COUNT(*)>=? AND COUNT(DISTINCT norm_ip(ip))>=? ORDER BY COUNT(*) DESC,path_family(path) LIMIT 20',(cutoff,now,config['min_attempts'],config['min_ips'])).fetchall()
            paths=[]
            for family,count,ips,first,last in groups:
                peers=c.execute('SELECT DISTINCT norm_ip(ip) FROM events WHERE path_family(path)=? AND ts BETWEEN ? AND ? ORDER BY 1 LIMIT 20',(family,cutoff,now)).fetchall()
                paths.append({'family':family,'count':count,'ips':ips,'first':first,'last':last,'peers':[row[0] for row in peers]})
    return credentials,paths


def campaigns_page():
    credentials,paths=campaign_patterns()
    peer_links=lambda row: ', '.join(ip_link(ip) for ip in row['peers'])+(' …' if row['ips']>20 else '')
    crows=''.join('<tr><td>'+esc(row['username'] or '(pusty)')+'</td><td><details><summary>Pokaż hasło</summary><code>'+esc(row['password'] or '(pusty)')+'</code></details></td><td>'+str(row['count'])+'</td><td>'+str(row['ips'])+'</td><td>'+peer_links(row)+'</td><td>'+stamp(row['first'])+' — '+stamp(row['last'])+'</td></tr>' for row in credentials)
    prows=''.join('<tr><td>'+esc(row['family'])+'</td><td>'+str(row['count'])+'</td><td>'+str(row['ips'])+'</td><td>'+peer_links(row)+'</td></tr>' for row in paths)
    return layout('Podobne wzorce botów', '<section class="box"><p>Okno: '+str(CONFIG['campaigns']['window_hours'])+' h · minimum '+str(CONFIG['campaigns']['min_ips'])+' IP i '+str(CONFIG['campaigns']['min_attempts'])+' prób.</p><p>Grupowanie jest heurystyką: wspólne dane logowania lub podobna rodzina ścieżek nie dowodzą, że adresy należą do jednego sprawcy. Każda tabela pokazuje do 20 grup i 20 adresów na grupę.</p></section><section class="box"><h2>Te same kombinacje z różnych IP</h2><table><tr><th>Login</th><th>Hasło</th><th>Próby</th><th>IP</th><th>Adresy</th><th>Zakres</th></tr>'+ (crows or '<tr><td colspan="6">Brak pasujących grup</td></tr>')+'</table></section><section class="box"><h2>Podobne ścieżki z różnych IP</h2><table><tr><th>Rodzina</th><th>Próby</th><th>IP</th><th>Adresy</th></tr>'+ (prows or '<tr><td colspan="4">Brak pasujących grup</td></tr>')+'</table></section>')


def daily_report_text(day):
    start=datetime.datetime.combine(day,datetime.time.min).timestamp()
    end=datetime.datetime.combine(day+datetime.timedelta(days=1),datetime.time.min).timestamp()
    with DB_LOCK:
        with db_connect() as c:
            http=c.execute('SELECT COUNT(*) FROM events WHERE ts>=? AND ts<?',(start,end)).fetchone()[0]
            sessions,longest=c.execute('SELECT COUNT(*),COALESCE(MAX(seconds),0) FROM endlessh_sessions WHERE started>=? AND started<?',(start,end)).fetchone()
            auth=c.execute('SELECT COUNT(*) FROM auth_events WHERE ts>=? AND ts<?',(start,end)).fetchone()[0]
            c.create_function('norm_ip',1,canonical_ip)
            new_ips=c.execute('SELECT COUNT(*) FROM (SELECT norm_ip(ip),MIN(ts) AS first FROM (SELECT ip,ts FROM events UNION ALL SELECT ip,started FROM endlessh_sessions UNION ALL SELECT ip,ts FROM auth_events) GROUP BY norm_ip(ip) HAVING first>=? AND first<?)',(start,end)).fetchone()[0]
            alerts=c.execute('SELECT COUNT(*) FROM alert_state WHERE active=1').fetchone()[0]
        if os.path.exists(CREDENTIALS_DB):
            with credentials_connect() as c:
                forms=c.execute('SELECT COUNT(*) FROM submissions WHERE ts>=? AND ts<?',(start,end)).fetchone()[0]
        else:
            forms=0
    # Only aggregate values leave the VPS; no submitted usernames or passwords.
    return ('📊 **FROG SOC '+VERSION+' | '+day.isoformat()+'**\nHTTP: '+str(http)+'\nSesje Endlessh: '+str(sessions)+'\nNajdłuższa sesja rozpoczęta tego dnia: %.3f s' % longest+'\nNowe IP w zachowanej historii: '+str(new_ips)+'\nNieudane logowania SSH: '+str(auth)+'\nFormularze pułapki: '+str(forms)+'\nAktywne alerty teraz: '+str(alerts)+'\nOkres: poprzedni dzień kalendarzowy w strefie serwera; dane według retencji.')


def maybe_send_daily_report(now=None):
    now=time.time() if now is None else now
    config=CONFIG['daily_report']
    if not config['enabled']:
        return False
    local=datetime.datetime.fromtimestamp(now)
    if (local.hour,local.minute)<(config['hour'],config['minute']):
        return False
    day=local.date()-datetime.timedelta(days=1)
    with REPORT_LOCK:
        with DB_LOCK:
            with db_connect() as c:
                last=meta_get(c,'daily_report_last','')
        if last>=day.isoformat():
            return False
        if not webhooks_notify(daily_report_text(day)):
            return False
        with DB_LOCK:
            with db_connect() as c:
                meta_set(c,'daily_report_last',day.isoformat())
                meta_set(c,'daily_report_sent',now)
        return True


def daily_report_worker():
    while True:
        try:
            maybe_send_daily_report()
        except Exception:
            logging.exception('Raport dzienny')
        time.sleep(60)


def reports_page():
    day=datetime.datetime.now().date()-datetime.timedelta(days=1)
    with DB_LOCK:
        with db_connect() as c:
            last=meta_get(c,'daily_report_last','—')
            sent=float(meta_get(c,'daily_report_sent','0'))
    config=CONFIG['daily_report']
    return layout('Raport dzienny Discord', '<section class="box"><p>Wysyłka: '+('włączona' if config['enabled'] else 'wyłączona')+' · godzina %02d:%02d' % (config['hour'],config['minute'])+' w strefie serwera. Wymaga skonfigurowanego .discord-webhook.</p><p>Ostatni wysłany dzień: '+esc(last)+' · wysłano: '+stamp(sent or None)+'</p><p>Po udanym wysłaniu stan jest zachowany w SQLite. Błąd dostarczenia powoduje ponowienie za około minutę. Po przestoju wysyłany jest tylko raport za ostatni zakończony dzień; bez nadrabiania całej zaległości.</p><h2>Podgląd za wczoraj</h2><pre>'+esc(daily_report_text(day))+'</pre><p>Raport zawiera tylko podsumowania liczbowe. Nie zawiera haseł ani loginów z pułapki.</p></section>')


TRAP_PROFILES = {
    'router': ('Gateway Manager', 'Network gateway configuration', '🌐'),
    'camera': ('IP Camera Console', 'Live camera management', '📹'),
    'nas': ('Storage Station', 'Files and shared volumes', '🗄️'),
    'admin': ('Administration Console', 'Infrastructure administration', '⚙️'),
    'wordpress': ('Site Publishing', 'Website publishing console', '📝'),
    'api': ('Developer API Console', 'API access and integration settings', '🔌')
}


def trap_profile(path):
    aliases={'/admin':'router','/login':'router','/cgi-bin/luci':'router','/wp-login.php':'wordpress','/wp-admin':'wordpress','/camera':'camera','/nas':'nas','/api/login':'api'}
    if path=='/':
        selected=CONFIG['honeypots']['homepage']
        return None if selected=='hub' else selected
    if path in aliases:
        profile=aliases[path]
        return profile if profile in CONFIG['honeypots']['enabled'] else None
    match=re.fullmatch(r'/traps/([a-z]+)(?:/login)?/?',path)
    return match[1] if match and match[1] in CONFIG['honeypots']['enabled'] else None


def trap_shell(title, content):
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+esc(title)+'</title><style>body{margin:0;background:#eef2f6;color:#203447;font:16px system-ui}header{background:#203447;color:white;padding:24px}main{max-width:1000px;margin:40px auto;padding:16px}section{background:white;padding:25px;border-radius:10px;border:1px solid #d2dce6}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px}a{color:#2261a0}label{display:block;margin:16px 0}input,button{padding:12px;font:inherit;box-sizing:border-box;max-width:100%;border:1px solid #bac8d4;border-radius:5px}input{width:100%}button{background:#2261a0;color:white}form{max-width:400px}small{color:#66798c}</style><header><b>'+esc(title)+'</b></header><main>'+content+'</main></html>'


def trap_hub():
    cards=''.join('<section><h2>'+TRAP_PROFILES[key][2]+' '+TRAP_PROFILES[key][0]+'</h2><p>'+TRAP_PROFILES[key][1]+'</p><a href="/traps/'+key+'">Open console →</a></section>' for key in CONFIG['honeypots']['enabled'])
    return trap_shell('Device Services Portal','<h1>Available services</h1><p>Select the device or service you want to manage.</p><div class="cards">'+cards+'</div><p><small>Configuration resources: <a href="/config.json">configuration</a> · <a href="/backup.zip">backup inventory</a></small></p>')


def trap_page(profile, failed=False):
    title,subtitle,icon=TRAP_PROFILES[profile]
    context={
        'router':'WAN uplink · LAN interfaces · Wireless settings',
        'camera':'Camera 01 · Video stream unavailable until sign-in',
        'nas':'Shared folders · Storage pool · User access',
        'admin':'System status · Maintenance · Access control',
        'wordpress':'Publishing dashboard · Themes · Site settings',
        'api':'API keys · Integrations · Request usage'
    }[profile]
    return trap_shell(title,'<p><a href="/">← All services</a></p><section><h1>'+icon+' '+esc(title)+'</h1><p>'+esc(subtitle)+'</p><p><small>'+esc(context)+'</small></p>'+('<p role="alert">Sign-in failed. Check your credentials.</p>' if failed else '')+'<form method="post" action="/traps/'+profile+'/login"><label>Username<input name="username" autocomplete="off" maxlength="256"></label><label>Password<input type="password" name="password" autocomplete="off" maxlength="512"></label><button>Sign in</button></form></section>')


def decoy_file(path):
    examples={
        '/.env':'# Demonstration configuration; no working credentials\nAPP_ENV=staging\nDB_HOST=192.0.2.10\nDB_PASSWORD=DECOY_NOT_A_REAL_SECRET\n',
        '/.git/config':'[core]\n    repositoryformatversion = 0\n[remote "origin"]\n    url = https://example.invalid/device-config.git\n',
        '/backup.zip':'Backup inventory (placeholder, not an archive)\nrouter-config.json\ncamera-settings.json\nNo real server files are exposed.\n',
        '/config.json':'{"environment":"staging","node":"demo-device","api":"https://example.invalid/api"}\n'
    }
    return examples[path]


def clean_agent(agent):
    return ''.join(char for char in str(agent) if ord(char)>=32 and ord(char)!=127)[:300]


def scan_classification(path):
    path=path.lower()
    checks=[
        ('Pliki konfiguracyjne',('konfiguracja',),lambda p: p.endswith('/.env') or p=='/.env' or p.endswith('/config.json')),
        ('Repozytorium Git',('metadane Git',),lambda p: '/.git/' in p),
        ('Kopie zapasowe',('nazwa archiwum',),lambda p: any(p.endswith(ext) for ext in ('.zip','.bak','.sql','.tar.gz'))),
        ('WordPress',('ścieżka WordPress',),lambda p: 'wp-' in p or '/wordpress' in p),
        ('Router / CGI',('CGI albo konsola routera',),lambda p: '/cgi-bin/' in p or '/traps/router' in p),
        ('Kamera IP',('konsola kamery',),lambda p: '/camera' in p),
        ('NAS',('konsola pamięci sieciowej',),lambda p: '/nas' in p),
        ('API',('ścieżka API',),lambda p: p.startswith('/api') or '/traps/api' in p),
        ('Panel administracyjny',('ścieżka logowania',),lambda p: '/admin' in p or '/login' in p)
    ]
    for label,reasons,predicate in checks:
        if predicate(path):
            return label, reasons[0]
    return 'Pozostały ruch','brak dopasowania do reguł ścieżek'


def observed_ip(ip):
    try:
        return canonical_ip(ip)
    except ValueError:
        return None


def bot_profile(ip):
    variants=ip_variants(ip);marks=','.join('?' for _ in variants)
    with DB_LOCK:
        with db_connect() as c:
            events=c.execute('SELECT e.ts,e.path,e.method,COALESCE(d.user_agent,\'\'),COALESCE(d.profile,\'\') FROM events e LEFT JOIN http_details d ON d.event_id=e.rowid WHERE e.ip IN ('+marks+') ORDER BY e.ts DESC,e.rowid DESC LIMIT 200',variants).fetchall()
            ssh=c.execute('SELECT started,seconds FROM endlessh_sessions WHERE ip IN ('+marks+') ORDER BY started DESC LIMIT 30',variants).fetchall()
            failures=c.execute('SELECT ts FROM auth_events WHERE ip IN ('+marks+') ORDER BY ts DESC LIMIT 30',variants).fetchall()
    agents=collections.Counter(row[3] for row in events if row[3])
    reasons=collections.defaultdict(set)
    for event in events:
        reasons[scan_classification(event[1])].add(event[1])
    ordered=list(reversed(events));visits=0;previous=None;steps=[]
    for ts,path,method,agent,profile in ordered:
        gap=None if previous is None else ts-previous
        if gap is None or gap>1800: visits+=1
        steps.append((ts,'HTTP '+method+' '+path,profile or '—',gap))
        previous=ts
    steps.extend((ts,'Endlessh: '+('brak CLOSE' if seconds is None else '%.3f s' % seconds),'SSH',None) for ts,seconds in ssh)
    steps.extend((ts[0],'Nieudane logowanie sshd/Dropbear','SSH auth',None) for ts in failures)
    if os.path.exists(CREDENTIALS_DB):
        with DB_LOCK:
            with credentials_connect() as c:
                forms=c.execute('SELECT ts,profile FROM submissions WHERE ip IN ('+marks+') ORDER BY ts DESC LIMIT 30',variants).fetchall()
        steps.extend((ts,'Wysłany formularz (bez ujawniania treści)',profile,None) for ts,profile in forms)
    rows=''.join('<tr><td>'+stamp(ts)+'</td><td>'+esc(detail)+'</td><td>'+esc(profile)+'</td><td>'+('—' if gap is None else str(gap)+' s')+'</td></tr>' for ts,detail,profile,gap in sorted(steps,key=lambda row:row[0],reverse=True)[:200])
    badges=''.join('<li><b>'+esc(label)+'</b>: '+esc(reason)+' · '+', '.join('<code>'+esc(path)+'</code>' for path in sorted(paths)[:5])+'</li>' for (label,reason),paths in sorted(reasons.items()))
    uas=''.join('<li><code>'+esc(agent)+'</code> · '+str(count)+' żądań</li>' for agent,count in agents.most_common(10))
    return '<section class="box"><h2>Profil bota i przebieg wizyty</h2><p>Do 200 ostatnich HTTP; wizyty rozdziela przerwa ponad 30 min. W tym wycinku: '+str(visits)+' wizyt. Jeden IP może reprezentować wiele urządzeń, a User-Agent może być podrobiony.</p><h3>Rozpoznane wzorce</h3><ul>'+ (badges or '<li>Brak HTTP</li>')+'</ul><p>Etykiety wskazują odwiedzane ścieżki, nie dowodzą złośliwości.</p><h3>User-Agent</h3><ul>'+ (uas or '<li>Brak danych (starsze wpisy nie zawierają nagłówka)</li>')+'</ul><table><tr><th>Czas</th><th>Zdarzenie</th><th>Pułapka</th><th>Odstęp HTTP</th></tr>'+rows+'</table></section>'


def run_health_checks():
    now=time.time();config=CONFIG['health_checks'];checks={}
    for name,url in (('Frog SOC','http://127.0.0.1:'+str(PORT)+'/health'),('Gatus',config['gatus_url'])):
        if not url:
            checks[name]={'ok':None,'detail':'Nie skonfigurowano endpointu HTTP','at':now}
            continue
        started=time.monotonic()
        try:
            request=urllib.request.Request(url,headers={'User-Agent':'FrogSOC-Health/6.0'})
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=config['timeout_seconds']) as response:
                code=response.status;body=response.read(256)
                ok=code==200 and (name!='Frog SOC' or body.strip()==b'ok')
            detail='HTTP '+str(code)+' · '+str(round((time.monotonic()-started)*1000))+' ms'
        except (OSError,ValueError) as exc:
            ok=False;detail='Brak poprawnej odpowiedzi HTTP ('+type(exc).__name__+')'
        checks[name]={'ok':ok,'detail':detail,'at':now}
    raw=command_output(['tailscale','status','--json'],timeout=3)
    try:
        status=json.loads(raw)
        online=status.get('Self',{}).get('Online')
        ok=status.get('BackendState')=='Running' and bool(status.get('TailscaleIPs')) and online is not False
        detail='Backend '+str(status.get('BackendState','?'))+' · online: '+('TAK' if online else 'NIE' if online is False else 'brak pola')
    except (ValueError,TypeError,AttributeError):
        ok=False;detail='Brak poprawnego statusu tailscale --json'
    checks['Tailscale']={'ok':ok,'detail':detail,'at':now}
    ports,_=net_ports();age=now-ENDLESSH_SUCCESS if ENDLESSH_SUCCESS else None
    ready=ENDLESSH_PORT in ports and age is not None and age<=config['endlessh_stale_seconds'] and not ENDLESSH_ERROR
    checks['Endlessh']={'ok':ready if ENDLESSH_SUCCESS or now-BOOT>30 else None,'detail':'Nasłuch: '+('TAK' if ENDLESSH_PORT in ports else 'NIE')+' · ostatni odczyt logu: '+('brak' if age is None else str(round(age))+' s temu'),'at':now}
    with HEALTH_LOCK:
        HEALTH_STATE.clear();HEALTH_STATE.update(checks)
    return checks


def health_worker():
    while True:
        try:
            run_health_checks()
        except Exception:
            logging.exception('Testy sprawności usług')
        time.sleep(CONFIG['health_checks']['interval_seconds'])


def health_page():
    with HEALTH_LOCK:
        checks=dict(HEALTH_STATE)
    rows=''.join('<tr><td>'+esc(name)+'</td><td>'+('OK' if row['ok'] else 'BŁĄD' if row['ok'] is False else 'N/D')+'</td><td>'+esc(row['detail'])+'</td><td>'+stamp(row['at'])+'</td></tr>' for name,row in checks.items())
    return layout('Sprawność usług', '<section class="box"><p>Testy co '+str(CONFIG['health_checks']['interval_seconds'])+' s. Gatus: odpowiedź HTTP, Tailscale: backend/adres/stan online, Endlessh: nasłuch i świeżość odczytu logów. Nie otwieramy dodatkowych sesji pułapki.</p><p>Stan Tailscale nie jest testem połączenia z konkretnym peerem. HTTP 200 Gatus nie potwierdza zdrowia wszystkich monitorowanych przez niego endpointów.</p><table><tr><th>Usługa</th><th>Stan</th><th>Szczegóły</th><th>Sprawdzono</th></tr>'+ (rows or '<tr><td colspan="4">Pierwszy test trwa</td></tr>')+'</table></section>')


def map_data(day=''):
    date=datetime.datetime.strptime(day,'%Y-%m-%d').date() if day else datetime.date.today()
    start=datetime.datetime.combine(date,datetime.time.min).timestamp()
    end=datetime.datetime.combine(date+datetime.timedelta(days=1),datetime.time.min).timestamp()
    with DB_LOCK:
        with db_connect() as c:
            c.create_function('norm_ip',1,observed_ip)
            rows=c.execute("SELECT g.ip,g.country,g.lat,g.lon,CAST(strftime('%H',e.ts,'unixepoch','localtime') AS INT),COUNT(*) FROM events e JOIN geo g ON norm_ip(e.ip)=g.ip WHERE e.ts>=? AND e.ts<? GROUP BY g.ip,CAST(strftime('%H',e.ts,'unixepoch','localtime') AS INT) ORDER BY COUNT(*) DESC,g.ip LIMIT 5000",(start,end)).fetchall()
            total=c.execute('SELECT COUNT(*) FROM events WHERE ts>=? AND ts<?',(start,end)).fetchone()[0]
    points=[{'ip':ip,'country':country,'lat':lat,'lon':lon,'hour':min(hour,23),'count':count} for ip,country,lat,lon,hour,count in rows]
    return {'day':date.isoformat(),'points':points,'http_total':total,'limit':5000}


def map_markup(demo=False):
    return '<svg id="world-map" viewBox="0 0 960 480" role="img" aria-label="Mapa aktywności IP" data-source="'+('/demo/data' if demo else '/geo/data')+'"><image href="/assets/world.svg" width="960" height="480"/><g id="map-dots"></g></svg><label>Godzina (narastająco): <output id="map-hour">23</output><input id="map-range" type="range" min="0" max="23" value="23"></label><button id="map-play" type="button">▶ Odtwórz dzień</button><p id="map-status" role="status">Wczytywanie mapy…</p>'


def map_page(day=''):
    date=datetime.datetime.strptime(day,'%Y-%m-%d').date() if day else datetime.date.today()
    return layout('Mapa i oś czasu', '<section class="box"><form action="/geo" method="get"><label>Dzień<input name="day" type="date" value="'+date.isoformat()+'"></label><button>Pokaż</button></form><p>Kontury Natural Earth · grupowanie w komórkach 5° · przybliżona geolokalizacja IP HTTP. Maks. 5000 grup IP/godzina, wyłącznie IP już zlokalizowane przez worker.</p>'+map_markup()+'<p>Geolokalizacja nie dowodzi pochodzenia osoby. Dane mapy nie są wysyłane do dostawcy kafelków.</p></section>')


def demo_data():
    samples=[('192.0.2.10','Polska',52,21),('198.51.100.20','USA',39,-98),('203.0.113.30','Japonia',36,138),('192.0.2.40','Brazylia',-15,-48),('198.51.100.50','Australia',-33,151)]
    return {'day':'DEMO','http_total':1248,'limit':5000,'points':[{'ip':ip,'country':country+' (fikcyjne)','lat':lat,'lon':lon,'hour':hour,'count':(i+1)*(hour+1)} for i,(ip,country,lat,lon) in enumerate(samples) for hour in (3,8,12,18,23)]}


def demo_page():
    content='<h1>🐸 Frog SOC · DEMO</h1><p>WYŁĄCZNIE FIKCYJNE DANE · bez odczytu historii serwera · bez zapisu formularzy</p><div class="cards"><section><h2>1248</h2><p>Żądań HTTP</p></section><section><h2>37</h2><p>Przykładowych IP</p></section><section><h2>12</h2><p>Sesji Endlessh</p></section><section><h2>🐸 Poziom 8</h2><p>Pokazowy rozwój żaby</p></section></div><section><h2>Profil przykładowego bota · 192.0.2.10</h2><p>12:00 GET / → 12:01 GET /.env → 12:02 GET /wp-login.php</p><p>Rozpoznanie: konfiguracja i WordPress · User-Agent: DemoBot/1.0</p><p>To przykładowa sekwencja, nie dane prawdziwej osoby.</p></section><section><h2>Mapa demonstracyjna</h2>'+map_markup(True)+'</section><p>Operacje administracyjne i kasowanie danych są niedostępne w demo.</p><script defer src="/assets/features.js"></script>'
    return trap_shell('Frog SOC — demonstracja',content)


def admin_token(scope):
    value=base64.urlsafe_b64encode(json.dumps({'scope':scope,'issued':time.time()}).encode()).decode()
    return value+'.'+hmac.new(CSRF_KEY,value.encode(),hashlib.sha256).hexdigest()


def verify_admin_token(token,scope):
    try:
        value,signature=token.split('.')
        if not secrets.compare_digest(signature,hmac.new(CSRF_KEY,value.encode(),hashlib.sha256).hexdigest()):
            raise ValueError('signature')
        payload=json.loads(base64.urlsafe_b64decode(value))
        issued=float(payload['issued'])
        if payload['scope']!=scope or not math.isfinite(issued) or not -30<=time.time()-issued<=1800:
            raise ValueError('expired')
    except (ValueError,TypeError,KeyError,UnicodeError):
        raise PermissionError('Nieprawidłowy token') from None


def change_rule(fields):
    def one(name,default=''):
        values=fields.get(name,[default])
        if len(values)!=1: raise ValueError('Powtórzone pole')
        return values[0]
    verify_admin_token(one('token'),'watch-rules')
    action=one('action','save');rule_id=int(one('id','0'))
    if action not in ('save','delete','toggle') or rule_id<0:
        raise ValueError('Nieprawidłowa operacja')
    if action=='save':
        name=one('name').strip();kind=one('kind');path=one('path').strip();window=int(one('window_seconds','60'));threshold=int(one('threshold','1'))
        if not name or len(name)>80 or kind not in ('path','panels') or not 1<=window<=86400 or not 1<=threshold<=10000:
            raise ValueError('Nieprawidłowa nazwa, typ lub próg reguły')
        if kind=='path' and (not path.startswith('/') or len(path)>150 or '*' in path[:-1] or any(ord(char)<32 for char in path)):
            raise ValueError('Podaj ścieżkę /... albo prefiks zakończony *')
        if kind=='panels' and threshold>6:
            raise ValueError('Reguła paneli obsługuje najwyżej 6 różnych profili')
    with DB_LOCK:
        with db_connect() as c:
            if action=='delete':
                c.execute('DELETE FROM watch_rules WHERE id=?',(rule_id,))
            elif action=='toggle':
                c.execute('UPDATE watch_rules SET enabled=1-enabled WHERE id=?',(rule_id,))
            elif rule_id:
                if not c.execute('UPDATE watch_rules SET name=?,kind=?,path=?,window_seconds=?,threshold=? WHERE id=?',(name,kind,path,window,threshold,rule_id)).rowcount:
                    raise ValueError('Nie znaleziono reguły')
            else:
                if c.execute('SELECT COUNT(*) FROM watch_rules').fetchone()[0]>=25:
                    raise ValueError('Maksymalnie 25 reguł')
                c.execute('INSERT INTO watch_rules (name,kind,path,window_seconds,threshold,enabled) VALUES (?,?,?,?,?,1)',(name,kind,path,window,threshold))


def rules_page(params=None):
    params=params or {};edit=int(params.get('edit','0'))
    with DB_LOCK:
        with db_connect() as c:
            rules=c.execute('SELECT id,name,kind,path,window_seconds,threshold,enabled FROM watch_rules ORDER BY id').fetchall()
    current=next((row for row in rules if row[0]==edit),(0,'Obserwuj backup','path','/backup.zip',60,1,1))
    token=admin_token('watch-rules')
    rows=[]
    for rule_id,name,kind,path,window,threshold,enabled in rules:
        actions='<a href="/rules?edit='+str(rule_id)+'">Edytuj</a><form method="post" action="/rules/save"><input type="hidden" name="token" value="'+esc(token)+'"><input type="hidden" name="id" value="'+str(rule_id)+'"><button name="action" value="toggle">'+('Wyłącz' if enabled else 'Włącz')+'</button><button name="action" value="delete">Usuń regułę</button></form>'
        rows.append('<tr><td>'+esc(name)+'</td><td>'+esc(kind)+' '+esc(path)+'</td><td>'+str(threshold)+' / '+str(window)+' s</td><td>'+('ON' if enabled else 'OFF')+'</td><td>'+actions+'</td></tr>')
    rule_id,name,kind,path,window,threshold,_=current
    form='<form method="post" action="/rules/save"><input type="hidden" name="token" value="'+esc(token)+'"><input type="hidden" name="id" value="'+str(rule_id)+'"><label>Nazwa<input name="name" maxlength="80" value="'+esc(name)+'" required></label><label>Typ<select name="kind"><option value="path"'+(' selected' if kind=='path' else '')+'>Żądania ścieżki / prefiksu</option><option value="panels"'+(' selected' if kind=='panels' else '')+'>Różne panele z jednego IP</option></select></label><label>Ścieżka / prefiks*<input name="path" value="'+esc(path)+'"></label><label>Okno sekund<input type="number" name="window_seconds" min="1" max="86400" value="'+str(window)+'"></label><label>Próg<input type="number" name="threshold" min="1" max="10000" value="'+str(threshold)+'"></label><button name="action" value="save">Zapisz regułę</button></form>'
    return layout('Własne reguły obserwacji','<section class="box"><p>Maks. 25 reguł, bez wyrażeń regularnych i wykonywania kodu. Typ path liczy żądania jednego IP dla ścieżki lub prefiksu z końcowym *. Typ panels liczy różne profile pułapek jednego IP; ścieżka jest wtedy pomijana.</p><p>Przykłady: /backup.zip, próg 1 w 60 s; różne panele, próg 5 w 60 s. Powiadomienia korzystają z Discorda i wyciszenia per reguła. Dane reguł są w SQLite i nie wymagają restartu.</p><table><tr><th>Nazwa</th><th>Warunek</th><th>Próg</th><th>Stan</th><th>Operacje</th></tr>'+''.join(rows)+'</table></section><section class="box"><h2>'+('Edytuj' if rule_id else 'Dodaj')+' regułę</h2>'+form+'</section>')


def rule_alerts(now=None):
    now=time.time() if now is None else now;alerts=[]
    with DB_LOCK:
        with db_connect() as c:
            c.create_function('norm_ip',1,observed_ip)
            c.create_function('trap_profile',1,trap_profile)
            rules=c.execute('SELECT id,name,kind,path,window_seconds,threshold FROM watch_rules WHERE enabled=1 ORDER BY id LIMIT 25').fetchall()
            for rule_id,name,kind,path,window,threshold in rules:
                if kind=='path':
                    if path.endswith('*'):
                        condition="e.path LIKE ? ESCAPE '\\'";value=path[:-1].replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%'
                    else:
                        condition='e.path=?';value=path
                    rows=c.execute('SELECT norm_ip(e.ip),COUNT(*) FROM events e WHERE e.ts BETWEEN ? AND ? AND norm_ip(e.ip) IS NOT NULL AND '+condition+' GROUP BY norm_ip(e.ip) HAVING COUNT(*)>=? ORDER BY COUNT(*) DESC LIMIT 5',(now-window,now,value,threshold)).fetchall()
                else:
                    rows=c.execute("SELECT norm_ip(e.ip),COUNT(DISTINCT COALESCE(NULLIF(d.profile,''),trap_profile(e.path))) FROM events e LEFT JOIN http_details d ON d.event_id=e.rowid WHERE e.ts BETWEEN ? AND ? AND norm_ip(e.ip) IS NOT NULL GROUP BY norm_ip(e.ip) HAVING COUNT(DISTINCT COALESCE(NULLIF(d.profile,''),trap_profile(e.path)))>=? ORDER BY 2 DESC LIMIT 5",(now-window,now,threshold)).fetchall()
                if rows:
                    alerts.append(('watch:'+str(rule_id),'Reguła '+name+': '+', '.join(ip+' ('+str(count)+')' for ip,count in rows)+' w '+str(window)+' s; do 5 adresów'))
    return alerts


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    initialize_db()
    load_events()
    # Bind first: monitoring must not report our own not-yet-started listener as failed.
    with Server((CONFIG['listen_host'], PORT), Handler) as server:
        threading.Thread(target=alert_worker, daemon=True).start()
        if CONFIG['geo_enabled']:
            threading.Thread(target=geo_worker, daemon=True).start()
        threading.Thread(target=maintenance_worker, daemon=True).start()
        threading.Thread(target=endlessh_worker, daemon=True).start()
        threading.Thread(target=daily_report_worker, daemon=True).start()
        threading.Thread(target=health_worker, daemon=True).start()
        server.serve_forever(poll_interval=0.5)
