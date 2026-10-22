#!/bin/sh
# Updates an existing Alpine/OpenRC installation; preserves password and config.
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Uruchom jako root / przez sudo'; exit 1; }
STAGE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APPDIR=/opt/frog-soc
[ -f "$APPDIR/app.py" ] && [ -f "$APPDIR/.soc-password" ]
BACKUP="$APPDIR/backups/v5-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
chmod 700 "$BACKUP"
cp -p "$APPDIR/app.py" "$BACKUP/app.py"
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
cp "$STAGE/app.py" "$APPDIR/.app-v5.tmp"
chown root:root "$APPDIR/.app-v5.tmp"
chmod 644 "$APPDIR/.app-v5.tmp"
mv "$APPDIR/.app-v5.tmp" "$APPDIR/app.py"
rollback() {
    cp -p "$BACKUP/app.py" "$APPDIR/app.py"
    if [ -f "$BACKUP/config.json" ]; then cp -p "$BACKUP/config.json" "$APPDIR/config.json"; fi
    rc-service frog-soc restart || true
    echo "Błąd wdrożenia. Przywrócono aplikację. Backup: $BACKUP" >&2
    exit 1
}
rc-service frog-soc restart || rollback
if ! python3 - <<'PY'
import base64, importlib.util, pathlib, time, urllib.request, urllib.error
spec=importlib.util.spec_from_file_location('verify','/opt/frog-soc/app.py')
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
password=pathlib.Path(app.PASSWORD_FILE).read_text().strip()
headers={'Authorization':'Basic '+base64.b64encode(('frog:'+password).encode()).decode()}
base='http://127.0.0.1:'+str(app.PORT)
for attempt in range(20):
    try:
        for path,marker in [('/health','ok'),('/soc','Aktywność'),('/ssh','Port źródłowy'),('/ssh?sort=longest','Historia Endlessh'),('/ssh.csv','duration_seconds'),('/activity','Wspólna aktywność'),('/settings','5.0'),('/frog','XP'),('/assets/live.js','setInterval')]:
            request=urllib.request.Request(base+path,headers=headers)
            with urllib.request.urlopen(request,timeout=5) as response:
                assert marker in response.read().decode(), path
        try:
            urllib.request.urlopen(urllib.request.Request(base+'/ssh?from=bad',headers=headers),timeout=5)
            raise AssertionError('Nieprawidłowy filtr nie został odrzucony')
        except urllib.error.HTTPError as exc:
            assert exc.code==400
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
printf 'Frog SOC 5.0 uruchomiony. Panel /ssh, /activity, /settings\nBackup: %s\n' "$BACKUP"
