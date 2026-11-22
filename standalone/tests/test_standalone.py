import http.client
import json
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/"app"), str(ROOT/"standalone")]
from runtime import Runtime, parse_snapshot
from ui import UI

BODY = b'proxies: [{name: fixture, type: http, server: 8.8.8.8, port: 443, tls: true}]'


class Standalone(unittest.TestCase):
    def setUp(self):
        self.dir = self.enterContext(tempfile.TemporaryDirectory())
        self.r = Runtime(self.dir)
        self.s = SimpleNamespace(runtime=self.r, tls=Mock(), lock=threading.Lock(), expiry=0, retry=0)
        self.s.tls.wrap_socket.side_effect = lambda sock, **kw: sock

    def request(self, path, data=None, cookie=''):
        # Real HTTP framing over a private socket pair. TLS wrapper is substituted.
        client, server = socket.socketpair()
        with client, server:
            body = json.dumps(data).encode() if data is not None else b''
            method = 'POST' if data is not None else 'GET'
            client.sendall(f'{method} {path} HTTP/1.0\r\nContent-Type: application/json\r\nCookie: {cookie}\r\nContent-Length: {len(body)}\r\n\r\n'.encode()+body)
            UI(server, ('local', 0), self.s)
            response = http.client.HTTPResponse(client)
            response.begin()
            return response.status, response.read(), response.getheader('Set-Cookie','').split(';')[0]

    def test_http_workflow(self):
        self.assertEqual(self.request('/status')[0], 403)
        _, _, cookie = self.request('/login', {'password':self.r.state['admin']})
        csrf = json.loads(self.request('/status', cookie=cookie)[1])['csrf']
        self.assertEqual(self.request('/enable', {}, cookie)[0], 403)
        url = 'https://test.example/fake-token'
        with patch('subscription.fetch', side_effect=lambda u,parse: parse(BODY)), patch.object(self.r,'check'):
            self.assertEqual(self.request('/save', dict(url=url,csrf=csrf),cookie)[0], 200)
            self.assertFalse(self.r.state['active'])
            self.assertNotIn(url,self.r.path.read_text())
            with patch.object(self.r, 'start') as start:
                self.assertEqual(self.request('/enable', dict(csrf=csrf),cookie)[0], 200)
                start.assert_called_once_with(self.r.state['saved'])
            status = self.request('/status',cookie=cookie)[1]
            self.assertNotIn(b'8.8.8.8',status)
            self.assertFalse(json.loads(status)['listening'])
            self.assertEqual(self.request('/disable',dict(csrf=csrf),cookie)[0],200)
        restored = Runtime(self.dir)
        self.assertEqual(restored.state['saved'],parse_snapshot(BODY))
        self.assertFalse(restored.state['active'])
        self.request('/logout',dict(csrf=csrf),cookie)
        self.assertEqual(self.request('/status',cookie=cookie)[0],403)

    def test_failed_switch_restores_previous(self):
        nodes = parse_snapshot(BODY)
        self.r.commit(active=nodes)
        with patch.object(self.r,'check'), patch.object(self.r,'start',side_effect=[ValueError(),None]) as start:
            with self.assertRaises(ValueError):
                self.r.switch([dict(nodes[0],port=8443)])
            self.assertEqual(start.call_args.args,(nodes,))
            self.assertEqual(self.r.state['active'],nodes)

    def test_projection(self):
        for bad in [BODY.replace(b'8.8.8.8',b'127.0.0.1'),BODY.replace(b'tls: true',b'dialer-proxy: DIRECT'),
                    BODY.replace(b'type: http',b'type: file')]:
            with self.assertRaises(ValueError):
                parse_snapshot(bad)
        cfg = self.r.config(parse_snapshot(BODY))
        self.assertEqual(cfg['rules'],['MATCH,upstream-1'])
        self.assertTrue(cfg['authentication'])
        self.assertNotIn('external-controller',cfg)

    def test_store_shape(self):
        root = ROOT/'standalone/store'
        manifest = yaml.safe_load((root/'config.yml').read_text())
        flow = yaml.safe_load((root/manifest['init_config']).read_text())
        docker = manifest['docker_config']
        self.assertEqual(docker['network_mode'],'bridge')
        self.assertFalse(docker['privileged_mode'] or docker['devices'] or docker['cap_add'])
        self.assertEqual(docker['volumes'],[dict(container='/data',host='/var/data/f1-standalone-mvp')])
        for path in (docker['icon'],manifest['app_info']):
            self.assertTrue((root/path).is_file())
        script = flow['steps'][flow['step_pointer']]['parameters']['shell_path']
        self.assertEqual(manifest['resource_files'],[dict(file_type='file',path=script)])
        self.assertTrue((root/'resource'/script).is_file())
        self.assertEqual({(p['network_protocol'],p['host'],p['container']) for p in docker['ports']},
                         {('tcp','17681','17680'),('tcp','17891','17890')})
