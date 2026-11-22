import hashlib
import http.client
import json
import socket
import ssl
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'app'), str(ROOT/'standalone')]
from runtime import Runtime
from ui import UI, pairing_context


class LocalTLS(unittest.TestCase):
    def test_fresh_pairing_and_login(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            conn, server = socket.socketpair()
            runtime = Runtime(directory)
            tls = pairing_context(directory, runtime.state['admin'])
            state = SimpleNamespace(tls=tls,runtime=runtime,lock=threading.Lock(),expiry=0,retry=0)
            lines = (directory/'pairing.txt').read_text().splitlines()
            context = ssl.create_default_context(cafile=str(directory/'ui.crt'))
            with conn, server:
                thread = threading.Thread(target=UI,args=(server,('local',0),state))
                thread.start()
                with context.wrap_socket(conn,server_hostname='F1 Standalone') as client:
                    self.assertEqual(hashlib.sha256(client.getpeercert(True)).hexdigest(),lines[0].split()[-1])
                    body = json.dumps({'password':lines[1].split()[-1]}).encode()
                    client.sendall(f'POST /login HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n'.encode()+body)
                    response = http.client.HTTPResponse(client)
                    response.begin()
                    self.assertEqual(response.status,200)
                    self.assertIn('Secure',response.getheader('Set-Cookie'))
                    response.read()
                thread.join(5)
                self.assertFalse(thread.is_alive())
