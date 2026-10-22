#!/bin/sh
# Fresh Alpine/OpenRC installation. Never replaces an existing Frog installation.
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Uruchom jako root'; exit 1; }
command -v apk >/dev/null 2>&1 || { echo 'Wymaga Alpine Linux'; exit 1; }
STAGE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ ! -e /opt/frog-soc/app.py ] || { echo 'Frog już istnieje; użyj deploy/deploy.sh'; exit 1; }
[ ! -e /etc/init.d/frog-soc ] || { echo 'Usługa frog-soc już istnieje'; exit 1; }
# Do not create a competing service beside an existing SSH tarpit.
if pidof endlessh >/dev/null 2>&1; then
    echo 'Endlessh już działa. Zachowaj jego usługę; po instalacji nie uruchamiaj frog-endlessh.'
    EXISTING_ENDLESSH=yes
else
    EXISTING_ENDLESSH=no
fi
apk add --no-cache python3 endlessh logrotate
[ ! -e /opt/frog-soc/.soc-password ] || { echo 'Hasło już istnieje; użyj aktualizacji'; exit 1; }
TMPDIR_FROG=$(mktemp -d)
trap 'rm -rf "$TMPDIR_FROG"' EXIT HUP INT TERM
cp "${1:-$STAGE/deploy/config.example.json}" "$TMPDIR_FROG/config.json"
FROG_ROOT="$TMPDIR_FROG" python3 - "$STAGE/deploy/app.py" <<'PYTHON'
import getpass, importlib.util, pathlib, sys
spec=importlib.util.spec_from_file_location('frog',sys.argv[1])
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
first=getpass.getpass('Nowe hasło panelu (min. 12 znaków): ')
second=getpass.getpass('Powtórz hasło panelu: ')
if len(first)<12 or first!=second:
    raise SystemExit('Hasła różne lub za krótkie. Usługi nie zostały uruchomione.')
p=pathlib.Path(app.PASSWORD_FILE);p.touch(mode=0o600);p.write_text(first+'\n')
PYTHON
mkdir -p /opt/frog-soc
cp "$STAGE/deploy/app.py" /opt/frog-soc/app.py
cp "$TMPDIR_FROG/config.json" /opt/frog-soc/config.json
cp "$TMPDIR_FROG/.soc-password" /opt/frog-soc/.soc-password
chmod 600 /opt/frog-soc/config.json /opt/frog-soc/.soc-password
cat > /etc/init.d/frog-soc <<'EOF'
#!/sbin/openrc-run
name="Frog SOC"
command="/usr/bin/python3"
command_args="/opt/frog-soc/app.py"
command_background=yes
pidfile="/run/frog-soc.pid"
output_log="/var/log/frog-soc.log"
error_log="/var/log/frog-soc.log"
depend() { need net; }
EOF
if [ "$EXISTING_ENDLESSH" = no ]; then
cat > /etc/init.d/frog-endlessh <<'EOF'
#!/sbin/openrc-run
name="Endlessh for Frog"
command="/usr/bin/endlessh"
command_args="$(python3 -c 'import json; c=json.load(open("/opt/frog-soc/config.json")); print("-p",int(c["endlessh_port"]),"-d 10000 -m 256 -v")')"
command_background=yes
pidfile="/run/frog-endlessh.pid"
output_log="/var/log/endlessh.log"
error_log="/var/log/endlessh.log"
depend() { need net; }
EOF
chmod 755 /etc/init.d/frog-endlessh
rc-update add frog-endlessh default
rc-service frog-endlessh start
fi
chmod 755 /etc/init.d/frog-soc
rc-update add frog-soc default
cp "$STAGE/deploy/frog-soc.logrotate" /etc/logrotate.d/frog-soc
rc-service frog-soc start
printf 'Frog zainstalowany. Dostosuj firewall/NAT do config.json.\n'
printf 'Dostęp do panelu przez localhost/tunel SSH lub osobno skonfigurowany Tailscale.\n'
printf 'Po zmianie portów: restart frog-soc i frog-endlessh (jeśli utworzono).\n'
