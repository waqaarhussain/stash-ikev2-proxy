#!/bin/bash
set -euo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
[[ $(uname -m) == x86_64 && -d /run/systemd/system ]] && command -v apt-get >/dev/null || {
    echo 'Requires an AMD64 Debian/Ubuntu VPS with systemd.' >&2; exit 1;
}
SOURCE=${STASH_SOURCE:-https://raw.githubusercontent.com/waqaarhussain/stash-ikev2-proxy/main}
LIB=/usr/local/lib/stash-ikev2-proxy
STATE=/var/lib/stash-ikev2-proxy
BIN=/usr/local/bin
install -d -m 700 /run/lock/stash-ikev2-proxy
exec 9>/run/lock/stash-ikev2-proxy/install.lock
flock -n 9 || { echo 'Another install is running.' >&2; exit 1; }
for helper in stash-exit add new link manage bench; do
    if [[ -e "$BIN/$helper" || -L "$BIN/$helper" ]]; then
        if [[ "$helper" == stash-exit ]]; then
            target="$LIB/manager.py"
        else
            target="$LIB/$helper"
        fi
        [[ $(readlink "$BIN/$helper" || true) == "$target" ]] || {
            echo "$BIN/$helper is already in use. Use a fresh VPS." >&2; exit 1;
        }
    fi
done
if [[ ! -e "$STATE/state.json" ]]; then
    if ss -H -lntu | awk '{print $5}' | grep -E ':(80|8443|18765|200[0-9]{2}|201[01][0-9]|2012[0-7])$' >/dev/null; then
        echo 'A required port is in use. Use a fresh VPS.' >&2; exit 1
    fi
fi

TEMP=$(mktemp -d)
trap 'rm -rf -- "$TEMP"' EXIT
fetch() {
    curl --proto '=https' -fsSL --retry 2 --connect-timeout 10 --max-time 120 "$1" -o "$2"
    printf '%s  %s\n' "$3" "$2" | sha256sum -c -
}
fetch "$SOURCE/manager.py" "$TEMP/manager.py" 5a3d6355dc235f2136dd6973e363d833d97c221cff4b1900a981346572db5cce
fetch https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-amd64.tar.gz \
    "$TEMP/sing-box.tgz" 699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968
fetch https://github.com/caddyserver/caddy/releases/download/v2.11.9/caddy_2.11.9_linux_amd64.tar.gz \
    "$TEMP/caddy.tgz" 5b8cb7faf8726a2028ad96a66e54e6e81e8f361bc6175e5d22bbd997cc5177fb
tar --no-same-owner -xzf "$TEMP/sing-box.tgz" -C "$TEMP" --strip-components=1 sing-box-1.14.4-linux-amd64/sing-box
tar --no-same-owner -xzf "$TEMP/caddy.tgz" -C "$TEMP" caddy

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl iproute2 python3 python3-yaml
python3 -m py_compile "$TEMP/manager.py"
install -d -m 755 "$LIB" /etc/stash-ikev2-proxy
install -m 755 "$TEMP/manager.py" "$LIB/manager.py"
install -m 755 "$TEMP/sing-box" "$LIB/sing-box"
install -m 755 "$TEMP/caddy" "$LIB/caddy"
id stash-exit >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin stash-exit
install -d -m 750 -o root -g stash-exit "$STATE"

if [[ ! -e "$STATE/state.json" ]]; then
    STASH_IP=$(curl --proto '=https' -4fsS --connect-timeout 10 --max-time 20 https://api.ipify.org)
    python3 - "$STATE/state.json" "$STASH_IP" <<'PY'
import grp
import ipaddress
import json
import os
import sys
from pathlib import Path

path, host = sys.argv[1:]
address = ipaddress.ip_address(host)
if address.version != 4 or not address.is_global or address.is_multicast:
    raise SystemExit('A public IPv4 address is required.')
temp = Path(path + '.new')
temp.write_text(json.dumps(dict(host=str(address), exits={}, devices={}, profiles=[])))
os.chown(temp, 0, grp.getgrnam('stash-exit').gr_gid)
temp.chmod(0o640)
temp.replace(path)
PY
fi
STASH_IP=$(python3 -c 'import ipaddress,json,sys; print(ipaddress.IPv4Address(json.load(open(sys.argv[1]))["host"]))' "$STATE/state.json")
cat > /etc/stash-ikev2-proxy/Caddyfile <<EOF
{
    admin off
    auto_https disable_redirects
    default_sni $STASH_IP
}
https://$STASH_IP:8443 {
    tls {
        issuer acme {
            dir https://acme-v02.api.letsencrypt.org/directory
            profile shortlived
            disable_tlsalpn_challenge
        }
    }
    reverse_proxy 127.0.0.1:18765
}
EOF
chmod 644 /etc/stash-ikev2-proxy/Caddyfile
"$LIB/caddy" adapt --config /etc/stash-ikev2-proxy/Caddyfile --validate >/dev/null

cat > /etc/systemd/system/stash-exit-engine.service <<'UNIT'
[Unit]
Description=Stash country exit engine
Wants=network-online.target
After=network-online.target

[Service]
User=stash-exit
RuntimeDirectory=stash-exit-engine
RuntimeDirectoryMode=0700
ExecStartPre=/usr/local/bin/stash-exit render /run/stash-exit-engine/engine.json
ExecStart=/usr/local/lib/stash-ikev2-proxy/sing-box run -c /run/stash-exit-engine/engine.json
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/stash-exit-profiles.service <<'UNIT'
[Unit]
Description=Stash private profile delivery

[Service]
User=stash-exit
ExecStart=/usr/local/bin/stash-exit serve
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/stash-exit-https.service <<'UNIT'
[Unit]
Description=HTTPS for Stash profile URLs
Wants=network-online.target
After=network-online.target stash-exit-profiles.service

[Service]
DynamicUser=true
StateDirectory=stash-exit-https
Environment=XDG_DATA_HOME=/var/lib/stash-exit-https/data
Environment=XDG_CONFIG_HOME=/var/lib/stash-exit-https/config
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/lib/stash-ikev2-proxy/caddy run --config /etc/stash-ikev2-proxy/Caddyfile --adapter caddyfile
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
chmod 644 /etc/systemd/system/stash-exit-{engine,profiles,https}.service
ln -sfn "$LIB/manager.py" "$BIN/stash-exit"
for helper in add new link manage bench; do
    printf '#!/bin/bash\nexec /usr/local/bin/stash-exit %s "$@"\n' "$helper" > "$LIB/$helper"
    chmod 755 "$LIB/$helper"
    ln -sfn "$LIB/$helper" "$BIN/$helper"
done
if command -v ufw >/dev/null && ufw status | grep -Fx 'Status: active' >/dev/null; then
    ufw allow 80/tcp
    ufw allow 8443/tcp
    ufw allow 20000:20127/tcp
    ufw allow 20000:20127/udp
fi
systemctl daemon-reload
systemctl enable stash-exit-{engine,profiles,https}.service
systemctl restart stash-exit-{engine,profiles,https}.service
echo 'Waiting for the trusted HTTPS certificate.'
for attempt in {1..45}; do
    if curl --noproxy '*' -fsS --resolve "$STASH_IP:8443:127.0.0.1" --max-time 3 \
        "https://$STASH_IP:8443/health" >/dev/null 2>&1; then
        systemctl is-active --quiet stash-exit-engine.service || {
            echo 'Proxy engine did not start. Check journalctl -u stash-exit-engine.' >&2
            exit 1
        }
        echo 'Ready. Run add, then new. Use link to retrieve a profile later.'
        exit 0
    fi
    sleep 2
done
echo 'HTTPS is pending. Check inbound TCP 80/8443 and journalctl -u stash-exit-https.' >&2
exit 1
