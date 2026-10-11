"""Exercise the production Rust transformer with an isolated, local-only core."""
import asyncio
import json
from pathlib import Path
import socket
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'windows-package/fixed-route-harness.exe'
CORE = ROOT / 'src-tauri/sidecar/verge-mihomo-x86_64-pc-windows-msvc.exe'


def transform(config):
    result = subprocess.run([str(HARNESS)], input=json.dumps(config), text=True,
                            capture_output=True, check=True, timeout=10)
    return yaml.safe_load(result.stdout)


class FixedRouteTests(unittest.IsolatedAsyncioTestCase):
    async def test_chain_success_failure_and_missing_exit(self):
        requests = []
        clients = set()

        async def relay(reader, writer):
            clients.add(writer)
            try:
                header = await reader.readuntil(b'\r\n\r\n')
                requests.append(header.split(b'\r\n')[0])
                writer.write(b'HTTP/1.1 200 OK\r\n\r\n')
                await writer.drain()
                version, length = await reader.readexactly(2)
                self.assertEqual(version, 5)
                await reader.readexactly(length)
                writer.write(b'\x05\x00')
                await writer.drain()
                request = await reader.readexactly(4)
                if request[3] == 3:
                    size = (await reader.readexactly(1))[0]
                    await reader.readexactly(size)
                else:
                    await reader.readexactly(4 if request[3] == 1 else 16)
                await reader.readexactly(2)
                writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01')
                await writer.drain()
                while data := await reader.read(4096):
                    writer.write(data)
                    await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                clients.discard(writer)
                writer.close()

        first = await asyncio.start_server(relay, '127.0.0.1', 0)
        try:
            for missing, domain_route in [(False, False), (True, False), (False, True), (True, True)]:
                with self.subTest(missing_exit=missing, domain_route=domain_route), tempfile.TemporaryDirectory(prefix='fixed-route-test-') as directory:
                    for database in ('geosite.dat', 'geoip.dat', 'Country.mmdb'):
                        shutil.copyfile(ROOT / 'src-tauri/resources' / database, Path(directory) / database)
                    with socket.socket() as reserve:
                        reserve.bind(('127.0.0.1', 0))
                        port = reserve.getsockname()[1]
                    config = transform({
                        'mode': 'global', 'mixed-port': port, 'allow-lan': False,
                        'bind-address': '127.0.0.1', 'dns': {'enable': False},
                        'tun': {'enable': False}, 'log-level': 'silent',
                        'proxies': [
                            {'name': 'Relay', 'type': 'http', 'server': '127.0.0.1', 'port': first.sockets[0].getsockname()[1]}
                        ] + ([] if missing else [
                            {'name': 'Fixed', 'type': 'socks5', 'server': '103.5.250.92', 'port': 443, 'dialer-proxy': 'Relay'}
                        ]),
                        'rules': ['MATCH,REJECT'],
                    })
                    # Use only one random test listener, pinned to the production fixed-exit group.
                    config['mixed-port'] = 0
                    config['listeners'][0]['port'] = port
                    if domain_route:
                        config['mixed-port'] = port
                        config['listeners'] = []
                    config['proxy-groups'][0]['url'] = 'http://127.0.0.1:1/isolated-health'
                    path = Path(directory) / 'config.json'
                    path.write_text(json.dumps(config), encoding='utf8')
                    log = (Path(directory) / 'core.log').open('wb')
                    proc = subprocess.Popen([str(CORE), '-d', directory, '-f', str(path)], stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW)
                    try:
                        async with asyncio.timeout(15):
                            while True:
                                if proc.poll() is not None:
                                    self.fail((Path(directory) / 'core.log').read_text())
                                try:
                                    reader, writer = await asyncio.open_connection('127.0.0.1', port)
                                    break
                                except OSError:
                                    await asyncio.sleep(0.1)
                        target = b'local-fixture.claude.ai' if domain_route else b'192.0.2.10'
                        writer.write(b'CONNECT ' + target + b':443 HTTP/1.1\r\nHost: ' + target + b':443\r\n\r\n')
                        await writer.drain()
                        await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
                        writer.write(b'fixture-echo')
                        await writer.drain()
                        reply = await asyncio.wait_for(reader.read(12), 8)
                        self.assertEqual(reply, b'' if missing else b'fixture-echo')
                        if not missing:
                            self.assertTrue(requests)
                            self.assertTrue(all(r == b'CONNECT 103.5.250.92:443 HTTP/1.1' for r in requests))
                            # Break the only simulated route. No real endpoint is contacted.
                            for client in tuple(clients):
                                client.close()
                            self.assertEqual(await asyncio.wait_for(reader.read(1), 5), b'')
                        writer.close()
                    finally:
                        proc.terminate()
                        await asyncio.to_thread(proc.wait, 10)
                        log.close()
        finally:
            first.close()
            for client in tuple(clients):
                client.close()
            await first.wait_closed()


if __name__ == '__main__':
    unittest.main()
