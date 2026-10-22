#!/usr/bin/env python3
"""Frog SOC 4.0; stdlib-only Alpine/OpenRC mini SOC."""
import base64
import collections
import datetime
import html
import hashlib
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
from urllib.parse import urlsplit, parse_qs

ROOT = '/opt/frog-soc'
EVENTFILE = ROOT + '/events.jsonl'
PASSWORD_FILE = ROOT + '/.soc-password'
PORT = 31888
TAILNET = ipaddress.ip_network('100.64.0.0/10')
EVENTS = collections.deque(maxlen=600)
LOCK = threading.Lock()
BOOT = time.time()
CACHE = {'at': 0, 'data': None}
MAX_ACTIVE = threading.BoundedSemaphore(12)
DB = ROOT + '/soc-history.sqlite3'
WEBHOOK_FILE = ROOT + '/.discord-webhook'
DB_LOCK = threading.Lock()
GEO_LOCK = threading.Lock()
ALERT_COOLDOWN = 900
ALERT_STATE = {}
GEO_REFRESH = 86400 * 30
ENDLESSH_ERROR = ''
ENDLESSH_UPDATED = 0
ENDLESSH_LOGS = ('/var/log/endlessh.log*',)


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
    c.execute('CREATE TABLE IF NOT EXISTS endlessh_seen (id TEXT PRIMARY KEY)')
    c.execute('CREATE TABLE IF NOT EXISTS endlessh_offsets (path TEXT PRIMARY KEY, device INTEGER, inode INTEGER, offset INTEGER)')
    return c


def initialize_db():
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
            c.execute('DELETE FROM events WHERE ts < ?', (int(time.time()) - 90 * 86400,))
            c.execute('DELETE FROM events WHERE rowid IN (SELECT rowid FROM events ORDER BY ts DESC LIMIT -1 OFFSET 30000)')


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
    try:
        with open(WEBHOOK_FILE, encoding='utf-8') as f:
            url = f.read().strip()
        if not url.startswith('https://discord.com/api/webhooks/') and not url.startswith('https://discordapp.com/api/webhooks/'):
            return
        body = json.dumps({'content': content[:1800], 'allowed_mentions': {'parse': []}}).encode()
        req = urllib.request.Request(url, body, {'Content-Type':'application/json','User-Agent':'FrogSOC/4.0'}, method='POST')
        with urllib.request.urlopen(req, timeout=6) as r:
            r.read(128)
    except (OSError, ValueError, urllib.error.URLError):
        pass


def alert_worker():
    while True:
        try:
            s = snapshot()
            alerts = [msg for level, msg in threat_alerts(s) if level != 'INFO']
            alerts += [svc['name'] + ': usluga niewykryta' for svc in s['services'] if not svc['ok']]
            ssh = ssh_failures()
            if ssh['count'] >= 10: alerts.append('SSH: >=10 nieudanych prob w dostepnych logach (' + str(ssh['count']) + ')')
            for msg in alerts[:8]:
                now = time.monotonic()
                if now - ALERT_STATE.get(msg, -99999) > ALERT_COOLDOWN:
                    ALERT_STATE[msg] = now
                    webhooks_notify('🚨 **FROG SOC 4.0** | ' + msg)
            # Keep disk bounded; full history is kept 90 days (or until user purges).
            if int(time.time()) % 3600 < 65:
                with DB_LOCK:
                    with db_connect() as c:
                        c.execute('DELETE FROM events WHERE ts < ?', (int(time.time()) - 90*86400,))
                        c.execute('DELETE FROM events WHERE rowid IN (SELECT rowid FROM events ORDER BY ts DESC LIMIT -1 OFFSET 30000)')
        except Exception:
            pass
        time.sleep(60)


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
            req = urllib.request.Request('https://ipwho.is/'+safe_ip, headers={'User-Agent':'FrogSOC/4.0'})
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
    if not c.execute('INSERT OR IGNORE INTO endlessh_seen VALUES (?)', (key,)).rowcount:
        return
    if kind == 'ACCEPT':
        c.execute('INSERT INTO endlessh_sessions VALUES (?,?,?,?,?,NULL,NULL)', (key, ip, port, fd, ts))
    else:
        # Pair by full peer tuple and nearest start; fd alone is reused by Endlessh.
        row = c.execute('SELECT id FROM endlessh_sessions WHERE ip=? AND port=? AND fd=? AND ended IS NULL AND started<=? ORDER BY ABS(started-?) LIMIT 1',
                        (ip, port, fd, ts, ts-seconds)).fetchone()
        if row:
            c.execute('UPDATE endlessh_sessions SET ended=?, seconds=? WHERE id=?', (ts, seconds, row[0]))
        else:
            # CLOSE is sufficient even when ACCEPT rotated away or logging began mid-session.
            c.execute('INSERT INTO endlessh_sessions VALUES (?,?,?,?,?,?,?)', (key, ip, port, fd, ts-seconds, ts, seconds))


def import_endlessh_logs():
    global ENDLESSH_ERROR, ENDLESSH_UPDATED
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


def endlessh_worker():
    global ENDLESSH_ERROR
    while True:
        try:
            import_endlessh_logs()
        except Exception as exc:
            ENDLESSH_ERROR = 'Błąd importu Endlessh: '+str(exc)
        time.sleep(5)


def ssh_page(page=1):
    data = ssh_failures()
    ports, established = net_ports()
    with DB_LOCK:
        with db_connect() as c:
            total = c.execute('SELECT COUNT(*) FROM endlessh_sessions').fetchone()[0]
            pages = max(1, (total+49)//50)
            page = min(max(1, page), pages)
            sessions = c.execute('SELECT ip,port,started,ended,seconds FROM endlessh_sessions ORDER BY started DESC,id DESC LIMIT 50 OFFSET ?', ((page-1)*50,)).fetchall()
    def stamp(ts):
        return esc(datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')) if ts is not None else '—'
    rows = ''.join('<tr><td>'+esc(ip)+'</td><td>'+str(port)+'</td><td>'+stamp(start)+'</td><td>'+stamp(end)+'</td><td>'+('%.3f s' % seconds if seconds is not None else 'brak CLOSE')+'</td></tr>' for ip,port,start,end,seconds in sessions)
    nav = ('<a href="/ssh?page='+str(page-1)+'">← Nowsze</a> ' if page>1 else '')
    nav += 'Strona '+str(page)+' / '+str(pages)
    if page<pages:
        nav += ' <a href="/ssh?page='+str(page+1)+'">Starsze →</a>'
    status = '<p class="muted">Import co 5 s. Ostatnia próba: '+stamp(ENDLESSH_UPDATED or None)+'.</p>'
    if ENDLESSH_ERROR:
        status += '<p>'+esc(ENDLESSH_ERROR)+'</p>'
    if not total:
        status += '<p>Brak zapisanych połączeń. Endlessh wymaga logowania (-v -s lub LogLevel 1 i -s) do syslog, albo -v do /var/log/endlessh.log. Sprawdź README.</p>'
    sshrows = ''.join('<tr><td>'+esc(ip)+'</td><td>'+str(n)+'</td></tr>' for ip,n in data['top_ips'])
    return layout('🪤 SSH / Endlessh', '<section class="box"><h2>Historia Endlessh · port 41888</h2><p>Nasłuch: '+('TAK' if 41888 in ports else 'NIE')+' · Aktywne TCP: '+str(established[41888])+' · Zapisane sesje: '+str(total)+'</p>'+status+'<p class="muted">Czasy według strefy serwera. Długość pochodzi z CLOSE Endlessh; brak CLOSE oznacza sesję otwartą lub niekompletne logi. Historia SQLite pozostaje po restarcie, bez automatycznego usuwania.</p><table><tr><th>IP</th><th>Port źródłowy</th><th>Początek</th><th>Koniec</th><th>Długość</th></tr>'+ (rows or '<tr><td colspan="5">Brak danych</td></tr>')+'</table><p>'+nav+'</p></section><section class="box"><h2>Nieudane logowania sshd / Dropbear</h2><p>To osobne dane, niezależne od Endlessh: '+str(data['count'])+' wpisów.</p><table>'+sshrows+'</table></section>')


def history_page():
    series=full_timeline(48)
    maxi=max([x['events'] for x in series]+[1])
    rows=''.join('<tr><td>'+esc(x['hour'])+'</td><td><div style="height:10px;background:#00ffaa;width:'+str(round(100*x['events']/maxi))+'%"></div></td><td>'+str(x['events'])+'</td></tr>' for x in series)
    return layout('📈 Historia ataków', '<section class="box"><h2>Historia 48h</h2><p>Łącznie w SQLite: '+str(total_events())+' zdarzeń, retencja 90 dni. Dotychczasowe pliki events.jsonl zostają nietknięte.</p><table>'+rows+'</table></section>')


def frog4():
    count=total_events()
    xp=count*10
    level=1+int(math.sqrt(xp/100))
    stage='🥚 Kijanka' if level<3 else '🐸 Żaba' if level<10 else '👑 Król żab' if level<25 else '🐉 Cyberżaba'
    badges=[name for limit,name in [(1,'Pierwszy skan'),(10,'Bot magnet'),(100,'Wartownik'),(500,'Obrońca'),(1000,'Soc master'),(5000,'Legendarny płaz')] if count>=limit]
    return layout('🐸 Ewolucja', '<section class="box" style="text-align:center"><div style="font-size:84px">🐸</div><h2>'+esc(stage)+'</h2><div class="big">LEVEL '+str(level)+'</div><p>'+str(xp)+' XP · '+str(count)+' zapisanych ataków HTTP</p><h2>Odznaki</h2><p>'+esc(' 🏅 '.join(badges) or 'Brak')+'</p></section>')


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


def log_event(ip, path, method):
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
                c.execute('INSERT INTO events VALUES (?,?,?,?)', (event['ts'], event['ip'], event['path'], event['method']))
    except sqlite3.Error:
        pass


def trusted(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_loopback or a in TAILNET
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
            {'name': 'Endlessh', 'ok': ('endlessh' in processes or 41888 in ports),
             'detail': 'Połączenia established na :41888: ' + str(established[41888])},
            {'name': 'Gatus', 'ok': 'gatus' in processes, 'detail': 'Wykrywanie procesu (nie health check)'},
            {'name': 'Tailscale', 'ok': 'tailscaled' in processes, 'detail': 'Wykrywanie procesu (nie status tunelu)'},
        ],
        'listen_ports': sorted(ports)[:40],
        'endlessh_connections': established[41888],
    }
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
    files = ['/var/log/auth.log', '/var/log/secure', '/var/log/messages']
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
    with LOCK:
        events = list(EVENTS)
    now = int(time.time())
    bins = [0] * 24
    for e in events:
        try:
            ago = now - int(e['ts'])
            if 0 <= ago < 86400:
                bins[23 - ago // 3600] += 1
        except (ValueError, TypeError, KeyError):
            pass
    start = now - now % 3600 - 23 * 3600
    return [{'hour': time.strftime('%d.%m %H:00', time.localtime(start + i * 3600)),
             'events': bins[i]} for i in range(24)]


def threat_alerts(s=None):
    s = s or snapshot()
    m, d = s['mem'], s['disk']
    mem_pct = m['used'] * 100 / max(m['total'], 1)
    disk_pct = d['used'] * 100 / max(d['total'], 1)
    ev, ips, _, last_hour = analytics()
    alerts = []
    if mem_pct >= 85:
        alerts.append(('WYSOKI', 'RAM przekracza 85%'))
    if disk_pct >= 85:
        alerts.append(('WYSOKI', 'Dysk przekracza 85%'))
    if last_hour >= 100:
        alerts.append(('UWAGA', 'Dużo żądań HTTP w ciągu godziny: ' + str(last_hour)))
    for ip, count in ips.most_common(5):
        if count >= 50:
            alerts.append(('UWAGA', 'IP ' + ip + ' wygenerowało ' + str(count) + ' żądań w buforze'))
    if not alerts:
        alerts.append(('INFO', 'Brak przekroczonych progów heurystycznych'))
    return alerts


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
    return layout('SOC 3.0 · Analiza zdarzeń',
        "<div class='grid'><section class='box'><h2>🚨 Alarmy heurystyczne</h2><ul>" + arows +
        "</ul></section><section class='box'><h2>🔑 Nieudane SSH</h2><div class='big'>" + str(ssh['count']) +
        "</div><p class='muted'>" + esc(ssh['note']) + '</p><p class="muted">Logi: ' +
        esc(', '.join(ssh['sources']) or 'nie znaleziono / brak dostępu') +
        '</p><table><tr><th>IP</th><th>Wpisy</th></tr>' + sshrows +
        "</table></section></div><div class='grid'><section class='box'><h2>📈 Żądania HTTP — ostatnie 24h</h2>" +
        '<p class="muted">Tylko zdarzenia znajdujące się w buforze (max 600), nie pełna historia.</p><table>' +
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
        "<meta http-equiv='refresh' content='30'>"
        "<title>Frog SOC 4.0 — " + esc(title) + "</title><style>"
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
        "</style><main><nav><b>🐸 FROG SOC 4.0</b> &nbsp; "
        "<a href='/soc'>Centrum</a><a href='/stats'>Ataki</a><a href='/frog'>Żaba</a>"
        "<a href='/investigate'>Analiza</a><a href='/history'>Historia</a><a href='/geo'>Mapa IP</a><a href='/ssh'>SSH</a><a href='/soc/json'>JSON</a></nav><h1>" + esc(title) + '</h1>' + content +
        "<p class='muted'>Odświeżanie co 30 s · dostęp tylko z Tailscale/localhost + hasło</p>"
        "</main></html>")


def analytics():
    with LOCK:
        ev = list(EVENTS)
    counts = collections.Counter(str(e.get('ip', '?')) for e in ev)
    paths = collections.Counter(str(e.get('path', '?')) for e in ev)
    now = time.time()
    last_hour = sum(1 for e in ev if 0 <= now - e.get('ts', 0) < 3600)
    return ev, counts, paths, last_hour


def center():
    s = snapshot()
    ev, ips, paths, last_hour = analytics()
    m = s['mem']; d = s['disk']
    mp = round(100 * m['used'] / max(1, m['total']))
    dp = round(100 * d['used'] / max(1, d['total']))
    alerts = []
    if mp >= 85:
        alerts.append('RAM przekracza 85%')
    if dp >= 85:
        alerts.append('Dysk przekracza 85%')
    for svc in s['services']:
        if not svc['ok']:
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
        "<section class='grid'>" + ''.join(blocks) + '</section>' +
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
    server_version = 'FrogSOC/4.0'
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
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
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

    def route(self):
        path = urlsplit(self.path).path
        if path in ('/soc', '/stats', '/frog', '/soc/json', '/investigate', '/geo', '/history', '/ssh'):
            if not self.authorized():
                return
            if path == '/soc/json':
                s = snapshot().copy()
                ev, ips, paths, hour = analytics()
                s.update({'ssh_log_sample': ssh_failures(), 'http_timeline_24h': timeline(), 'top_processes': process_top(), 'alerts': threat_alerts(s), 'http_events_buffered': len(ev), 'http_events_last_hour': hour,
                          'top_ips': ips.most_common(10), 'top_paths': paths.most_common(10)})
                self.send(200, json.dumps(s, ensure_ascii=False), 'application/json; charset=utf-8')
            else:
                if path == '/ssh':
                    try:
                        page = int(parse_qs(urlsplit(self.path).query).get('page', ['1'])[0])
                    except ValueError:
                        page = 1
                    self.send(200, ssh_page(page))
                    return
                self.send(200, {'/soc': center, '/stats': stats, '/frog': frog, '/investigate': investigations, '/geo': geo_page, '/history': history_page, '/ssh': ssh_page}[path]())
            return
        if path == '/health':
            self.send(200, 'ok', 'text/plain; charset=utf-8')
            return
        log_event(self.client_address[0], path, self.command)
        if path in ('/', '/admin', '/login', '/cgi-bin/luci'):
            self.send(200, '<!doctype html><meta charset="utf-8"><title>Router Management</title>'
                      '<h2>Administrator login</h2><form method="post" action="/login">'
                      '<input name="username" placeholder="Username">'
                      '<input type="password" name="password" placeholder="Password">'
                      '<button>Sign in</button></form>')
        else:
            self.send(404, '<!doctype html><title>404</title><h2>404 Not Found</h2>')
        # No request body is consumed or logged, including attempted passwords.


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


if __name__ == '__main__':
    initialize_db()
    load_events()
    threading.Thread(target=alert_worker, daemon=True).start()
    threading.Thread(target=geo_worker, daemon=True).start()
    threading.Thread(target=endlessh_worker, daemon=True).start()
    with Server(('0.0.0.0', PORT), Handler) as server:
        server.serve_forever(poll_interval=0.5)