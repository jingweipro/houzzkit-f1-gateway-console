"""Run inside the candidate with --network none and a mounted tests directory."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'app'), str(ROOT/'standalone'), '/opt/console']
from runtime import Runtime


class Upstream(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        if self.path != 'example.invalid:443':
            return self.send_error(403)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'fixture-ok')

    def log_message(self,*args):
        pass


@unittest.skipUnless(shutil.which('mihomo'), 'requires actual Mihomo executable')
class Core(unittest.TestCase):
    def test_both_inbound_protocols(self):
        upstream = ThreadingHTTPServer(('127.0.0.1',0),Upstream)
        thread = threading.Thread(target=upstream.serve_forever)
        thread.start()
        self.addCleanup(upstream.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(upstream.shutdown)
        with tempfile.TemporaryDirectory() as tmp:
            r = Runtime(tmp)
            self.addCleanup(r.stop)
            # Construct private upstream solely inside the isolated smoke test.
            r.switch([dict(name='fixture',type='http',server='127.0.0.1',port=upstream.server_port)])
            with socket.create_connection(('127.0.0.1',17890),3) as sock, sock.makefile('rb') as stream:
                sock.sendall(b'CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n')
                self.assertIn(b' 407 ',stream.readline())
            password = r.state['proxy'].encode()
            for protocol in ('http','socks'):
                with socket.create_connection(('127.0.0.1',17890),3) as sock, sock.makefile('rb') as stream:
                    if protocol == 'http':
                        auth = base64.b64encode(b'client:'+password)
                        sock.sendall(b'CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\nProxy-Authorization: Basic '+auth+b'\r\n\r\n')
                        self.assertIn(b' 200 ',stream.readline())
                        while stream.readline().strip():
                            pass
                    else:
                        sock.sendall(b'\x05\x01\x02')
                        self.assertEqual(stream.read(2),b'\x05\x02')
                        sock.sendall(b'\x01\x06client'+bytes([len(password)])+password)
                        self.assertEqual(stream.read(2),b'\x01\x00')
                        sock.sendall(b'\x05\x01\x00\x03\x0fexample.invalid\x01\xbb')
                        version, result, _, kind = stream.read(4)
                        self.assertEqual((version,result),(5,0))
                        stream.read({1:4,4:16}[kind]+2)
                    self.assertEqual(stream.read(10),b'fixture-ok')
            r.switch([])
            self.assertFalse(r.healthy())
