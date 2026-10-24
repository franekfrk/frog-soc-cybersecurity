#!/bin/sh
# Updates an existing Alpine/OpenRC installation; preserves password and config.
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Uruchom jako root / przez sudo'; exit 1; }
STAGE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APPDIR=/opt/frog-soc
[ -f "$APPDIR/app.py" ] && [ -f "$APPDIR/.soc-password" ]
[ -s "$STAGE/features.js" ] && [ -s "$STAGE/world.svg" ]
BACKUP="$APPDIR/backups/v6-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
chmod 700 "$BACKUP"
cp -p "$APPDIR/app.py" "$BACKUP/app.py"
for asset in features.js world.svg ssh_trap.py; do
    if [ -f "$APPDIR/$asset" ]; then cp -p "$APPDIR/$asset" "$BACKUP/$asset"; fi
done
if [ -f "$APPDIR/config.json" ]; then
    cp -p "$APPDIR/config.json" "$BACKUP/config.json"
else
    cp "$STAGE/config.example.json" "$APPDIR/config.json"
    chmod 600 "$APPDIR/config.json"
fi
OLD_ENDLESSH=0; OLD_SSH=0; OLD_ENDLESSH_BOOT=0; OLD_SSH_BOOT=0
rc-service endlessh status >/dev/null 2>&1 && OLD_ENDLESSH=1
rc-service frog-ssh status >/dev/null 2>&1 && OLD_SSH=1
rc-update show default | grep -q ' endlessh ' && OLD_ENDLESSH_BOOT=1
rc-update show default | grep -q ' frog-ssh ' && OLD_SSH_BOOT=1
if [ -f /etc/init.d/frog-ssh ]; then cp -p /etc/init.d/frog-ssh "$BACKUP/frog-ssh.openrc"; fi
CHANGED=0; SUCCESS=0
rollback() {
    rc-service frog-ssh stop >/dev/null 2>&1 || true
    cp -p "$BACKUP/app.py" "$APPDIR/app.py"
    for asset in features.js world.svg ssh_trap.py; do
        if [ -f "$BACKUP/$asset" ]; then cp -p "$BACKUP/$asset" "$APPDIR/$asset"; else rm -f "$APPDIR/$asset"; fi
    done
    cp -p "$BACKUP/config.json" "$APPDIR/config.json"
    if [ -f "$BACKUP/frog-ssh.openrc" ]; then cp -p "$BACKUP/frog-ssh.openrc" /etc/init.d/frog-ssh; else rm -f /etc/init.d/frog-ssh; fi
    if [ "$OLD_ENDLESSH_BOOT" = 1 ]; then rc-update add endlessh default >/dev/null 2>&1 || true; else rc-update del endlessh default >/dev/null 2>&1 || true; fi
    if [ "$OLD_SSH_BOOT" = 1 ]; then rc-update add frog-ssh default >/dev/null 2>&1 || true; else rc-update del frog-ssh default >/dev/null 2>&1 || true; fi
    if [ "$OLD_SSH" = 1 ]; then rc-service frog-ssh start || true; fi
    if [ "$OLD_ENDLESSH" = 1 ]; then rc-service endlessh start || true; fi
    rc-service frog-soc restart || true
    echo "Błąd wdrożenia. Przywrócono aplikację i poprzednią pułapkę SSH. Backup: $BACKUP" >&2
}
finish() {
    code=$?
    trap - EXIT
    if [ "$CHANGED" = 1 ] && [ "$SUCCESS" != 1 ]; then rollback; exit 1; fi
    exit "$code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
# Validate configuration with the new application before changing the running service.
python3 - "$STAGE/app.py" <<'PY'
import importlib.util, sys, os
spec=importlib.util.spec_from_file_location('preflight',sys.argv[1])
app=importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
# Explicit opt-in for this rollout; later updates preserve disabled profiles.
import json, pathlib
if os.environ.get('FROG_ENABLE_NEW_TRAPS') == '1' or os.environ.get('FROG_ENABLE_SSH_CAPTURE') == '1':
    target=pathlib.Path('/opt/frog-soc/config.json')
    config=json.loads(target.read_text())
    hp=config.setdefault('honeypots',{})
    enabled=hp.setdefault('enabled',list(app.DEFAULT_CONFIG['honeypots']['enabled']))
    if os.environ.get('FROG_ENABLE_NEW_TRAPS')=='1':
        if 'phpmyadmin' not in enabled: enabled.append('phpmyadmin')
        hp['docker_api']=True
    if os.environ.get('FROG_ENABLE_SSH_CAPTURE')=='1':
        config['ssh_capture']={'enabled':True,'spool':'/var/lib/frog-ssh/attempts.sqlite3'}
        patterns=config.setdefault('endlessh_logs',list(app.DEFAULT_CONFIG['endlessh_logs']))
        if '/var/lib/frog-ssh/sessions.log*' not in patterns: patterns.append('/var/lib/frog-ssh/sessions.log*')
        services=config.setdefault('required_services',list(app.DEFAULT_CONFIG['required_services']))
        services[:]=['SSH Capture' if name=='Endlessh' else name for name in services]
    temporary=pathlib.Path(sys.argv[1]).parent/'config-traps.json'
    try:
        fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as f: json.dump(config,f,indent=2)
        app.load_config(temporary)
    except Exception:
        if temporary.exists(): temporary.unlink()
        raise
print('Konfiguracja poprawna; port HTTP:',app.PORT,'Endlessh:',app.ENDLESSH_PORT)
PY
CANDIDATE="$APPDIR/config.json"
if [ -f "$STAGE/config-traps.json" ]; then CANDIDATE="$STAGE/config-traps.json"; fi
SSH_ENABLED=$(python3 - "$CANDIDATE" <<'PYCODE'
import json,sys
print(int(json.load(open(sys.argv[1])).get('ssh_capture',{}).get('enabled',False)))
PYCODE
)
if [ "$SSH_ENABLED" = 1 ]; then
    apk add --no-cache py3-paramiko
    python3 -c 'import paramiko; assert tuple(int(x) for x in paramiko.__version__.split(".")[:2]) >= (3,5)'
    grep -q '^frogssh:' /etc/group || addgroup -S frogssh
    id frogssh >/dev/null 2>&1 || adduser -S -D -H -s /sbin/nologin -G frogssh frogssh
    mkdir -p /var/lib/frog-ssh
    chown frogssh:frogssh /var/lib/frog-ssh
    chmod 700 /var/lib/frog-ssh
    # start-stop-daemon opens output after dropping privileges.
    touch /var/log/frog-ssh.log
    chown frogssh:frogssh /var/log/frog-ssh.log
    chmod 600 /var/log/frog-ssh.log
    python3 -m py_compile "$STAGE/ssh_trap.py"
fi
# Install log rotation support before modifying the application.
if ! command -v logrotate >/dev/null 2>&1; then
    apk add --no-cache logrotate
fi
python3 - "$BACKUP" <<'PY'
import os, sqlite3, sys
source='/opt/frog-soc/soc-history.sqlite3'
if os.path.exists(source):
    with sqlite3.connect(source) as src, sqlite3.connect(sys.argv[1]+'/soc-history.sqlite3') as dst:
        src.backup(dst)
PY
CHANGED=1
for asset in features.js world.svg ssh_trap.py; do
    cp "$STAGE/$asset" "$APPDIR/.$asset.tmp"
    chown root:root "$APPDIR/.$asset.tmp"
    chmod 644 "$APPDIR/.$asset.tmp"
    mv "$APPDIR/.$asset.tmp" "$APPDIR/$asset"
done
cp "$STAGE/app.py" "$APPDIR/.app-v6.tmp"
chown root:root "$APPDIR/.app-v6.tmp"
chmod 644 "$APPDIR/.app-v6.tmp"
mv "$APPDIR/.app-v6.tmp" "$APPDIR/app.py"
if [ -f "$STAGE/config-traps.json" ]; then
    cp "$STAGE/config-traps.json" "$APPDIR/.config-traps.tmp"
    chmod 600 "$APPDIR/.config-traps.tmp"
    mv "$APPDIR/.config-traps.tmp" "$APPDIR/config.json"
fi
if [ "$SSH_ENABLED" = 1 ]; then
    SSH_PORT=$(python3 - "$APPDIR/config.json" <<'PYCODE'
import json,sys
print(int(json.load(open(sys.argv[1])).get('endlessh_port',41888)))
PYCODE
)
    sed "s/--port 41888 /--port $SSH_PORT /" "$STAGE/frog-ssh.openrc" > /etc/init.d/frog-ssh
    chmod 755 /etc/init.d/frog-ssh
    if rc-service endlessh status >/dev/null 2>&1; then rc-service endlessh stop; fi
    rc-service frog-ssh restart
    rc-update add frog-ssh default
    rc-update del endlessh default >/dev/null 2>&1 || true
fi
rc-service frog-soc restart
if ! python3 - <<'PY'
import base64, contextlib, importlib.util, io, pathlib, re, secrets, sqlite3, time, urllib.request, urllib.error, urllib.parse, zipfile
spec=importlib.util.spec_from_file_location('verify','/opt/frog-soc/app.py')
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
password=pathlib.Path(app.PASSWORD_FILE).read_text().strip()
headers={'Authorization':'Basic '+base64.b64encode(('frog:'+password).encode()).decode()}
base='http://127.0.0.1:'+str(app.PORT)
for attempt in range(20):
    try:
        for path,marker in [('/updates','Co nowego'),('/compare','Porównania okresów'),('/ip?ip=192.0.2.1','Notatka i etykieta IP'),('/health','ok'),('/soc','Aktywność'),('/ssh','Port źródłowy'),('/ssh?sort=longest','Historia Endlessh'),('/ssh.csv','duration_seconds'),('/activity','Wspólna aktywność'),('/settings','6.5'),('/rules','Własne reguły'),('/healthchecks','Sprawność usług'),('/geo','Mapa i oś czasu'),('/geo/data','points'),('/demo','WYŁĄCZNIE FIKCYJNE'),('/assets/world.svg','<svg'),('/assets/features.js','world-map'),('/credential-stats','Statystyki prób'),('/campaigns','wzorce botów'),('/reports','Raport dzienny'),('/credentials','Formularze pułapki'),('/frog','XP'),('/assets/live.js','setInterval')]:
            if path=='/demo' and not app.CONFIG['demo_enabled']: continue
            request=urllib.request.Request(base+path,headers=headers)
            with urllib.request.urlopen(request,timeout=5) as response:
                assert marker in response.read().decode(), path
        if app.CONFIG['honeypots']['docker_api']:
            with urllib.request.urlopen(base+'/v1.43/version',timeout=5) as response:
                assert response.headers.get_content_type()=='application/json'
                assert b'ApiVersion' in response.read()
        for profile in app.CONFIG['honeypots']['enabled']:
            with urllib.request.urlopen(base+app.TRAP_PATHS[profile],timeout=5) as response:
                page=response.read().decode()
                assert 'action="'+app.TRAP_LOGIN_PATHS[profile]+'"' in page
                assert app.TRAP_DEVICES[profile]['model'] in page
                for field in app.TRAP_FORM_FIELDS[profile]: assert 'name="'+field+'"' in page
        try:
            urllib.request.urlopen(urllib.request.Request(base+'/ssh?from=bad',headers=headers),timeout=5)
            raise AssertionError('Nieprawidłowy filtr nie został odrzucony')
        except urllib.error.HTTPError as exc:
            assert exc.code==400
        with urllib.request.urlopen(base+'/',timeout=5) as response:
            public=response.read().decode().lower()
            assert response.headers['Server']=='WebServer'
            assert not any(marker in public for marker in ('/traps','frog soc','endlessh','honeypot'))
        with urllib.request.urlopen(base+'/backup.zip',timeout=5) as response:
            assert response.headers.get_content_type()=='application/zip'
            with zipfile.ZipFile(io.BytesIO(response.read())) as archive:
                assert archive.testzip() is None
                assert len(archive.namelist())==2
        for path in ('/demo','/demo/data','/assets/features.js','/assets/world.svg'):
            try:
                urllib.request.urlopen(base+path,timeout=5)
                raise AssertionError('Zasób panelu jest publiczny: '+path)
            except urllib.error.HTTPError as exc:
                assert exc.code==401
        if app.CONFIG['capture_credentials']:
            profile='wordpress' if 'wordpress' in app.CONFIG['honeypots']['enabled'] else app.CONFIG['honeypots']['enabled'][0]
            user_field,password_field=app.TRAP_FORM_FIELDS[profile]
            username='__frog_check__'+secrets.token_hex(8)
            password=secrets.token_hex(16)
            try:
                data=urllib.parse.urlencode({user_field:username,password_field:password}).encode()
                with urllib.request.urlopen(urllib.request.Request(base+app.TRAP_LOGIN_PATHS[profile],data=data),timeout=5) as response:
                    assert response.status==200
                with contextlib.closing(sqlite3.connect(app.CREDENTIALS_DB)) as c:
                    row=c.execute('SELECT id,profile FROM submissions WHERE username=? AND password=?',(username,password)).fetchone()
                    assert row is not None and row[1]==profile
                with urllib.request.urlopen(urllib.request.Request(base+'/credentials',headers=headers),timeout=5) as response:
                    page=response.read().decode()
                token=re.search('name="token" value="([^"]+)"',page).group(1)
                deletion=urllib.parse.urlencode({'token':token,'confirm':'USUN','action':'selected','id':row[0]}).encode()
                with urllib.request.urlopen(urllib.request.Request(base+'/credentials/delete',data=deletion,headers=headers),timeout=5) as response:
                    assert response.status==200
                with contextlib.closing(sqlite3.connect(app.CREDENTIALS_DB)) as c:
                    assert c.execute('SELECT COUNT(*) FROM submissions WHERE username=?',(username,)).fetchone()[0]==0
            finally:
                with contextlib.closing(sqlite3.connect(app.CREDENTIALS_DB)) as c:
                    c.execute('DELETE FROM submissions WHERE username=?',(username,))
                    c.commit()
            assert pathlib.Path(app.CREDENTIALS_DB).stat().st_mode & 0o777 == 0o600
            print('Zapis formularza, usuwanie przez panel i uprawnienia bazy: OK (wpis testowy usunięty)')
        print('HTTP, filtry, CSV, aktywność, konfiguracja, XP i JS: OK')
        break
    except Exception:
        if attempt==19: raise
        time.sleep(1)
PY
then
    exit 1
fi
rc-service frog-soc status
if [ "$SSH_ENABLED" = 1 ]; then
    rc-service frog-ssh status
    python3 - <<'PYCODE'
import importlib.util,socket,paramiko,sqlite3,time,secrets,contextlib,pwd,pathlib,hashlib,base64
spec=importlib.util.spec_from_file_location('app','/opt/frog-soc/app.py');app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
pid=int(pathlib.Path('/run/frog-ssh.pid').read_text())
status=pathlib.Path('/proc/'+str(pid)+'/status').read_text()
uid=int(next(line for line in status.splitlines() if line.startswith('Uid:')).split()[1])
assert uid==pwd.getpwnam('frogssh').pw_uid and uid!=0, 'SSH trap must run as unprivileged frogssh'
user='__frog_ssh_check__'+secrets.token_hex(8);password=secrets.token_hex(16)
try:
    for attempt in range(30):
        try:
            sock=socket.create_connection(('127.0.0.1',app.ENDLESSH_PORT),timeout=2);break
        except OSError:
            if attempt==29:raise
            time.sleep(.2)
    transport=paramiko.Transport(sock)
    try:
        transport.start_client(timeout=5)
        try: transport.auth_password(user,password,fallback=False)
        except paramiko.AuthenticationException: pass
        else: raise AssertionError('Honeypot accepted authentication')
    finally:transport.close()
    for attempt in range(30):
        with app.credentials_connect() as c:
            row=c.execute('SELECT password,profile FROM submissions WHERE username=?',(user,)).fetchone()
        if row:
            assert row==(password,'ssh');break
        time.sleep(.3)
    else:raise AssertionError('SSH credential import failed')
    print('Negocjacja SSH, zapis/import hasła, odmowa logowania: OK')
    hostkey=paramiko.RSAKey.from_private_key_file('/var/lib/frog-ssh/host_rsa')
    print('Klucz hosta pułapki RSA: SHA256:'+base64.b64encode(hashlib.sha256(hostkey.asbytes()).digest()).decode().rstrip('='))
finally:
    with contextlib.closing(sqlite3.connect(app.CONFIG['ssh_capture']['spool'],timeout=3)) as c, c:
        c.execute('PRAGMA secure_delete=ON');c.execute('DELETE FROM attempts WHERE username=?',(user,))
    with app.credentials_connect() as c:c.execute('DELETE FROM submissions WHERE username=?',(user,))
PYCODE
fi
# Keep an explicit, bounded log rotation recipe. Copytruncate has a small race window.
if command -v logrotate >/dev/null 2>&1 && [ -f "$STAGE/frog-soc.logrotate" ]; then
    cp "$STAGE/frog-soc.logrotate" /etc/logrotate.d/frog-soc
fi
SUCCESS=1
printf 'Frog SOC 6.5 uruchomiony. Panel /ssh, /activity, /settings\nBackup: %s\n' "$BACKUP"
