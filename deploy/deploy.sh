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
for asset in features.js world.svg; do
    if [ -f "$APPDIR/$asset" ]; then cp -p "$APPDIR/$asset" "$BACKUP/$asset"; fi
done
if [ -f "$APPDIR/config.json" ]; then
    cp -p "$APPDIR/config.json" "$BACKUP/config.json"
else
    cp "$STAGE/config.example.json" "$APPDIR/config.json"
    chmod 600 "$APPDIR/config.json"
fi
# Validate configuration with the new application before changing the running service.
python3 - "$STAGE/app.py" <<'PY'
import importlib.util, sys
spec=importlib.util.spec_from_file_location('preflight',sys.argv[1])
app=importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
print('Konfiguracja poprawna; port HTTP:',app.PORT,'Endlessh:',app.ENDLESSH_PORT)
PY
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
for asset in features.js world.svg; do
    cp "$STAGE/$asset" "$APPDIR/.$asset.tmp"
    chown root:root "$APPDIR/.$asset.tmp"
    chmod 644 "$APPDIR/.$asset.tmp"
    mv "$APPDIR/.$asset.tmp" "$APPDIR/$asset"
done
cp "$STAGE/app.py" "$APPDIR/.app-v6.tmp"
chown root:root "$APPDIR/.app-v6.tmp"
chmod 644 "$APPDIR/.app-v6.tmp"
mv "$APPDIR/.app-v6.tmp" "$APPDIR/app.py"
rollback() {
    cp -p "$BACKUP/app.py" "$APPDIR/app.py"
    for asset in features.js world.svg; do
        if [ -f "$BACKUP/$asset" ]; then cp -p "$BACKUP/$asset" "$APPDIR/$asset"; else rm -f "$APPDIR/$asset"; fi
    done
    if [ -f "$BACKUP/config.json" ]; then cp -p "$BACKUP/config.json" "$APPDIR/config.json"; fi
    rc-service frog-soc restart || true
    echo "Błąd wdrożenia. Przywrócono aplikację. Backup: $BACKUP" >&2
    exit 1
}
rc-service frog-soc restart || rollback
if ! python3 - <<'PY'
import base64, contextlib, importlib.util, pathlib, re, secrets, sqlite3, time, urllib.request, urllib.error, urllib.parse
spec=importlib.util.spec_from_file_location('verify','/opt/frog-soc/app.py')
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
password=pathlib.Path(app.PASSWORD_FILE).read_text().strip()
headers={'Authorization':'Basic '+base64.b64encode(('frog:'+password).encode()).decode()}
base='http://127.0.0.1:'+str(app.PORT)
for attempt in range(20):
    try:
        for path,marker in [('/health','ok'),('/soc','Aktywność'),('/ssh','Port źródłowy'),('/ssh?sort=longest','Historia Endlessh'),('/ssh.csv','duration_seconds'),('/activity','Wspólna aktywność'),('/settings','6.1'),('/rules','Własne reguły'),('/healthchecks','Sprawność usług'),('/geo','Mapa i oś czasu'),('/geo/data','points'),('/demo','WYŁĄCZNIE FIKCYJNE'),('/assets/world.svg','<svg'),('/assets/features.js','world-map'),('/credential-stats','Statystyki prób'),('/campaigns','wzorce botów'),('/reports','Raport dzienny'),('/credentials','Formularze pułapki'),('/frog','XP'),('/assets/live.js','setInterval')]:
            if path=='/demo' and not app.CONFIG['demo_enabled']: continue
            request=urllib.request.Request(base+path,headers=headers)
            with urllib.request.urlopen(request,timeout=5) as response:
                assert marker in response.read().decode(), path
        for profile in app.CONFIG['honeypots']['enabled']:
            with urllib.request.urlopen(base+app.TRAP_PATHS[profile],timeout=5) as response:
                assert 'action="'+app.TRAP_LOGIN_PATHS[profile]+'"' in response.read().decode()
        try:
            urllib.request.urlopen(urllib.request.Request(base+'/ssh?from=bad',headers=headers),timeout=5)
            raise AssertionError('Nieprawidłowy filtr nie został odrzucony')
        except urllib.error.HTTPError as exc:
            assert exc.code==400
        if app.CONFIG['capture_credentials']:
            username='__frog_check__'+secrets.token_hex(8)
            password=secrets.token_hex(16)
            try:
                data=urllib.parse.urlencode({'username':username,'password':password}).encode()
                with urllib.request.urlopen(urllib.request.Request(base+'/login',data=data),timeout=5) as response:
                    assert response.status==200
                with contextlib.closing(sqlite3.connect(app.CREDENTIALS_DB)) as c:
                    row=c.execute('SELECT id FROM submissions WHERE username=? AND password=?',(username,password)).fetchone()
                    assert row is not None
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
    rollback
fi
rc-service frog-soc status || rollback
# Keep an explicit, bounded log rotation recipe. Copytruncate has a small race window.
if command -v logrotate >/dev/null 2>&1 && [ -f "$STAGE/frog-soc.logrotate" ]; then
    cp "$STAGE/frog-soc.logrotate" /etc/logrotate.d/frog-soc
fi
printf 'Frog SOC 6.1 uruchomiony. Panel /ssh, /activity, /settings\nBackup: %s\n' "$BACKUP"
