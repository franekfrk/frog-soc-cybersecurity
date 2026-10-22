#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Uruchom: sudo sh ~/frog-update/deploy.sh'; exit 1; }
STAGE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APPDIR=/opt/frog-soc
[ -f "$APPDIR/app.py" ] && [ -f "$APPDIR/.soc-password" ]
python3 -m py_compile "$STAGE/app.py"
BACKUP="$APPDIR/backups/endlessh-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
chmod 700 "$BACKUP"
cp -p "$APPDIR/app.py" "$BACKUP/app.py"
python3 - "$BACKUP" <<'PY'
import os, sqlite3, sys
source = '/opt/frog-soc/soc-history.sqlite3'
if os.path.exists(source):
    with sqlite3.connect(source) as src, sqlite3.connect(sys.argv[1]+'/soc-history.sqlite3') as dst:
        src.backup(dst)
PY
cp "$STAGE/app.py" "$APPDIR/.app-endlessh.tmp"
chown root:root "$APPDIR/.app-endlessh.tmp"
chmod 644 "$APPDIR/.app-endlessh.tmp"
mv "$APPDIR/.app-endlessh.tmp" "$APPDIR/app.py"
rollback() {
    cp -p "$BACKUP/app.py" "$APPDIR/app.py"
    rc-service frog-soc restart || true
    echo "Błąd wdrożenia. Przywrócono aplikację. Backup: $BACKUP" >&2
    exit 1
}
rc-service frog-soc restart || rollback
if ! python3 - <<'PY'
import base64, pathlib, time, urllib.request
password = pathlib.Path('/opt/frog-soc/.soc-password').read_text().strip()
headers = {'Authorization': 'Basic '+base64.b64encode(('frog:'+password).encode()).decode()}
for attempt in range(20):
    try:
        with urllib.request.urlopen('http://127.0.0.1:31888/health', timeout=3) as response:
            assert response.read() == b'ok'
        req = urllib.request.Request('http://127.0.0.1:31888/ssh', headers=headers)
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read().decode()
            assert 'Historia Endlessh' in body
            assert 'Port źródłowy' in body
        print('HTTP /health i autoryzowany panel /ssh: OK')
        break
    except Exception:
        if attempt == 19:
            raise
        time.sleep(1)
PY
then
    rollback
fi
rc-service frog-soc status || rollback
python3 - <<'PY'
import sqlite3, time
for attempt in range(10):
    with sqlite3.connect('/opt/frog-soc/soc-history.sqlite3') as c:
        count = c.execute('SELECT COUNT(*) FROM endlessh_sessions').fetchone()[0]
        sources = c.execute('SELECT COUNT(*) FROM endlessh_offsets').fetchone()[0]
    if sources:
        print('Import logów: OK; zapisane sesje:', count)
        break
    time.sleep(1)
else:
    print('UWAGA: brak odczytanych logów. Sprawdź komunikat w /ssh.')
PY
printf 'Aktualizacja gotowa. Panel: /ssh\nBackup: %s\n' "$BACKUP"
