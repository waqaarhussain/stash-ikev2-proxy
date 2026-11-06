#!/usr/bin/python3
import argparse
import copy
import fcntl
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from getpass import getpass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import yaml

STATE = Path('/var/lib/stash-ikev2-proxy/state.json')
ENGINE = '/usr/local/lib/stash-ikev2-proxy/sing-box'
UNIT = 'stash-exit-engine.service'
FIRST_PORT, LAST_PORT = 20000, 20127
CIPHER = 'aes-128-gcm'
CONTROL_D = '76.76.2.22'


def load():
    return json.loads(STATE.read_text())


def save(state):
    with tempfile.NamedTemporaryFile(mode='w', dir=STATE.parent, delete=False) as stream:
        path = Path(stream.name)
        try:
            os.fchown(stream.fileno(), 0, STATE.parent.stat().st_gid)
            os.fchmod(stream.fileno(), 0o640)
            json.dump(state, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
            path.replace(STATE)
        finally:
            path.unlink(missing_ok=True)


def dns_url(value):
    if not re.fullmatch(r'https://dns\.controld\.com/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)?', value):
        raise ValueError('Enter the device’s full https://dns.controld.com/ resolver URL.')
    return value


def upstream_host(value):
    try:
        address = ipaddress.ip_address(value)
        if not address.is_global or address.is_multicast:
            raise ValueError('Upstream proxy IP must be public.')
        return str(address)
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', value):
            raise ValueError('Use a public proxy IP or a hostname.')
        return value.lower()


def port(value):
    if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 65535:
        raise ValueError('Port must be between 1 and 65535.')
    return int(value)


def label(prompt):
    value = input(prompt).strip()
    if not value or len(value) > 64 or not value.isprintable():
        raise ValueError('Use a name of 1 to 64 printable characters.')
    return value


def pick(items, prompt, display=str):
    if not items:
        raise ValueError('There are no entries to select.')
    for index, item in enumerate(items, 1):
        print(f'{index}. {display(item)}')
    selection = input(prompt).strip()
    if selection == '0':
        raise ValueError('Cancelled.')
    if not selection.isascii() or not selection.isdecimal() or not 1 <= int(selection) <= len(items):
        raise ValueError('Invalid selection.')
    return items[int(selection) - 1]


def exit_details():
    kind = pick(['http', 'socks', 'shadowsocks'], 'Proxy type: ',
                {'http': 'HTTP', 'socks': 'SOCKS5', 'shadowsocks': 'Shadowsocks'}.__getitem__)
    details = {'type': kind, 'server': upstream_host(input('Proxy host: ').strip()),
               'server_port': port(input('Proxy port: ').strip())}
    if kind == 'shadowsocks':
        methods = ['aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
                   'xchacha20-ietf-poly1305', '2022-blake3-aes-128-gcm',
                   '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305',
                   'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'aes-128-cfb',
                   'aes-192-cfb', 'aes-256-cfb', 'rc4-md5', 'chacha20-ietf', 'xchacha20']
        details['method'] = pick(methods, 'Cipher: ')
        details['password'] = getpass('Proxy password: ')
        if not details['password']:
            raise ValueError('A Shadowsocks password is required.')
    else:
        if kind == 'socks':
            details['version'] = '5'
        user = input('Proxy username (blank for IP allowlisting): ').strip()
        if user:
            details.update(username=user, password=getpass('Proxy password: '))
    if kind != 'http':
        details['udp'] = input('Does this provider support UDP relay? [y/N] ').strip().lower() == 'y'
    return details


def outbound(tag, details):
    proxy = {key: value for key, value in details.items() if key != 'udp'}
    proxy.update(tag=tag, domain_resolver='upstream-bootstrap')
    return proxy


def engine_config(state):
    dns = [{'type': 'local', 'tag': 'upstream-bootstrap'}]
    inbounds, outbounds, rules = [], [], []
    for index, details in enumerate(state['exits'].values()):
        outbounds.append(outbound(f'exit-{index}', details))
    exit_tags = dict(zip(state['exits'], (proxy['tag'] for proxy in outbounds)))
    for index, (device, resolver) in enumerate(state['devices'].items()):
        tag = f'doh-{index}'
        dns.append({'type': 'https', 'tag': tag, 'server': CONTROL_D,
                    'path': urlsplit(resolver).path,
                    'tls': {'enabled': True, 'server_name': 'dns.controld.com'}})
        for profile in state['profiles']:
            if profile['device'] != device:
                continue
            inbound = f"profile-{profile['port']}"
            details = state['exits'][profile['exit']]
            settings = {'type': 'shadowsocks', 'tag': inbound, 'listen': '0.0.0.0',
                        'listen_port': profile['port'], 'method': CIPHER,
                        'password': profile['password'], 'udp_timeout': '5m'}
            if not details.get('udp'):
                settings['network'] = 'tcp'
            inbounds.append(settings)
            rules.extend([
                {'inbound': inbound, 'action': 'resolve', 'server': tag, 'strategy': 'ipv4_only'},
                {'inbound': inbound, 'ip_is_private': True, 'action': 'reject'},
                {'inbound': inbound, 'action': 'route', 'outbound': exit_tags[profile['exit']]},
            ])
    rules.append({'action': 'reject'})
    return {'log': {'level': 'warn'}, 'dns': {'servers': dns, 'final': 'upstream-bootstrap',
                                            'independent_cache': True},
            'inbounds': inbounds, 'outbounds': outbounds, 'route': {'rules': rules}}


def checked(config, path):
    path.write_text(json.dumps(config))
    result = subprocess.run([ENGINE, 'check', '-c', str(path)], capture_output=True)
    if result.returncode:
        raise ValueError('sing-box rejected the configuration. Check the proxy type and credentials.')


def restart(state):
    subprocess.run(['systemctl', 'restart', UNIT], check=True)
    expected = {str(p['port']) for p in state['profiles']}
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        pid = subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', UNIT], text=True).strip()
        listeners = subprocess.check_output(['ss', '-H', '-ltnp'], text=True)
        owned = {line.split()[3].rsplit(':', 1)[-1] for line in listeners.splitlines()
                 if f'pid={pid},' in line}
        if pid != '0' and expected <= owned and subprocess.run(
                ['systemctl', 'is-active', '--quiet', UNIT]).returncode == 0:
            return
        time.sleep(.15)
    raise ValueError('The proxy engine did not open its expected listeners.')


def apply(before, after):
    if after == before:
        return
    with tempfile.TemporaryDirectory() as directory:
        checked(engine_config(after), Path(directory) / 'engine.json')
    save(after)
    try:
        restart(after)
    except (ValueError, OSError, subprocess.CalledProcessError):
        save(before)
        restart(before)
        raise


def config_url(state, profile):
    return f"https://{state['host']}:8443/s/{profile['token']}/config.yaml"


def stash_config(state, profile):
    resolver = state['devices'][profile['device']]
    details = state['exits'][profile['exit']]
    return {
        'mode': 'rule', 'log-level': 'info', 'ipv6': False,
        'dns': {'default-nameserver': [CONTROL_D], 'nameserver': [resolver],
                'proxy-server-nameserver': [resolver], 'follow-rule': False,
                'fake-ip-filter': ['*']},
        'proxies': [{'name': 'Exit: ' + profile['exit'], 'type': 'ss', 'server': state['host'],
                     'port': profile['port'], 'cipher': CIPHER, 'password': profile['password'],
                     'udp': details.get('udp', False)}],
        'rules': ['DOMAIN,dns.controld.com,DIRECT', f"MATCH,Exit: {profile['exit']}"],
    }


def profile_label(profile):
    return f"{profile['device']} / {profile['exit']}"


def free_port(state):
    used = {p['port'] for p in state['profiles']}
    for candidate in range(FIRST_PORT, LAST_PORT + 1):
        if candidate in used:
            continue
        try:
            with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
                tcp.bind(('0.0.0.0', candidate))
                udp.bind(('0.0.0.0', candidate))
        except OSError:
            continue
        return candidate
    raise ValueError('No profile ports are available.')


def new_profile(state):
    exit_name = pick(list(state['exits']), 'Choose country/exit: ')
    device = pick([None, *state['devices']], 'Choose device: ',
                  lambda item: item or 'Add a new device')
    if device is None:
        device = label('Device name: ')
        if device in state['devices']:
            raise ValueError('Device already exists. Select it from the device list.')
        state['devices'][device] = dns_url(getpass('This device’s Control D DoH URL: ').strip())
    if any(p['device'] == device and p['exit'] == exit_name for p in state['profiles']):
        raise ValueError('This device already has a profile for that exit. Run link.')
    profile = {'device': device, 'exit': exit_name, 'port': free_port(state),
               'token': secrets.token_urlsafe(32), 'password': secrets.token_urlsafe(32)}
    state['profiles'].append(profile)
    return profile


class Profiles(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        match = re.fullmatch(r'/s/([A-Za-z0-9_-]{43})/config\.yaml', self.path)
        if self.path == '/health':
            return self.respond(200, 'ok\n', 'text/plain')
        if match:
            state = load()
            for profile in state['profiles']:
                if hmac.compare_digest(match[1], profile['token']):
                    return self.respond(200, yaml.safe_dump(stash_config(state, profile), sort_keys=False),
                                        'application/yaml')
        self.respond(404, 'Not found\n', 'text/plain')

    def respond(self, status, body, content_type):
        payload = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def bench(state):
    for name, details in state['exits'].items():
        with tempfile.TemporaryDirectory() as directory, socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            local_port = sock.getsockname()[1]
            config = {'log': {'disabled': True},
                      'dns': {'servers': [{'type': 'local', 'tag': 'upstream-bootstrap'}]},
                      'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': local_port}],
                      'outbounds': [outbound('test', details)], 'route': {'final': 'test'}}
            path = Path(directory) / 'bench.json'
            checked(config, path)
            sock.close()
            with subprocess.Popen([ENGINE, 'run', '-c', str(path)], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL) as process:
                try:
                    for _ in range(20):
                        if process.poll() is not None:
                            break
                        try:
                            with socket.create_connection(('127.0.0.1', local_port), timeout=.1):
                                break
                        except OSError:
                            time.sleep(.05)
                    result = subprocess.run(
                        ['curl', '-fsS', '--noproxy', '', '--max-time', '20',
                         '--proxy', f'socks5h://127.0.0.1:{local_port}',
                         '-w', '\nHTTP %{http_code}, total %{time_total}s\n', 'https://ipinfo.io/json'],
                        capture_output=True, text=True)
                    print(f'{name}: {result.stdout.strip() if result.returncode == 0 else "Exit check failed."}')
                finally:
                    if process.poll() is None:
                        process.terminate()


def manage(state):
    action = pick(['Edit exit', 'Remove exit', 'Change device DNS', 'Revoke profile', 'List profiles'],
                  'Choose action: ')
    if action in ('Edit exit', 'Remove exit'):
        name = pick(list(state['exits']), 'Choose exit: ')
        if action == 'Edit exit':
            details = exit_details()
            if bool(details.get('udp')) != bool(state['exits'][name].get('udp')):
                print('Refresh this exit’s profiles in Stash to apply the changed UDP setting.')
            state['exits'][name] = details
        else:
            if any(p['exit'] == name for p in state['profiles']):
                raise ValueError('Revoke the profiles using this exit first.')
            del state['exits'][name]
    elif action == 'Change device DNS':
        device = pick(list(state['devices']), 'Choose device: ')
        state['devices'][device] = dns_url(getpass('New Control D DoH URL: ').strip())
        print('Refresh this device’s profiles in Stash after the change succeeds.')
    elif action == 'Revoke profile':
        profile = pick(state['profiles'], 'Choose profile: ', profile_label)
        state['profiles'].remove(profile)
    else:
        for profile in state['profiles']:
            print(profile_label(profile))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['add', 'new', 'link', 'manage', 'bench', 'serve', 'render'])
    parser.add_argument('path', nargs='?')
    args = parser.parse_args()
    if args.command == 'serve':
        ThreadingHTTPServer(('127.0.0.1', 18765), Profiles).serve_forever()
        return
    if args.command == 'render':
        Path(args.path).write_text(json.dumps(engine_config(load())))
        return
    if os.geteuid() != 0:
        raise ValueError('Run as root.')
    with (STATE.parent / 'admin.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = load()
        state = copy.deepcopy(before)
        if args.command == 'link':
            profile = pick(state['profiles'], 'Choose profile: ', profile_label)
            print(config_url(state, profile))
            return
        if args.command == 'bench':
            bench(state)
            return
        profile = None
        if args.command == 'add':
            name = label('Country/exit label: ')
            if name in state['exits'] or ',' in name or name in ('DIRECT', 'REJECT'):
                raise ValueError('Choose a unique exit label without commas or reserved rule names.')
            state['exits'][name] = exit_details()
        elif args.command == 'new':
            profile = new_profile(state)
        else:
            manage(state)
        apply(before, state)
        if profile:
            print(config_url(state, profile))


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        sys.exit(1)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
