import importlib.util
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
from unittest import mock
import unittest
import urllib.request
import urllib.error
import yaml
BASE=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/"app"))
import agent

class TestAgentSecurity(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=BASE)
  self.root=pathlib.Path(self.tmp.name)
  for attr in ("BASE","CFG_DIR","CONFIG","STATUS","STATE"):
   self.addCleanup(setattr,agent,attr,getattr(agent,attr))
  for target in ("agent.active","socket.getaddrinfo","socket.create_connection"):
   stub=mock.patch(target,return_value=False) if target=="agent.active" else mock.patch(target,side_effect=AssertionError("offline"))
   stub.start()
   self.addCleanup(stub.stop)
  agent.BASE=self.root;agent.CFG_DIR=self.root/"config"
  agent.CFG_DIR.mkdir()
  agent.CONFIG=agent.CFG_DIR/"config.yaml"
  agent.STATUS=self.root/"status.json"
  agent.STATE=self.root/"private"
  self.original={
   "mixed-port":17890,"redir-port":17893,"tproxy-port":17894,
   "dns":{"enable":True,"listen":"127.0.0.1:53"},
   "proxy-providers":{"Demo":{"type":"http","url":"https://example.org/private?token=SUPERSECRET",
      "path":"./provider.yaml","interval":43200}},
   "proxy-groups":[
    {"name":"AI_FIXED_US","type":"select","proxies":["AI-US-DEDICATED"]},
    {"name":"REGION_SG","type":"url-test","use":["Demo"]},
    {"name":"REGION_JP","type":"url-test","use":["Demo"]},
    {"name":"REGION_TW","type":"url-test","use":["Demo"]},
    {"name":"REGION_US","type":"url-test","use":["Demo"]},
    {"name":"NON_HK_REGION","type":"fallback","proxies":["REGION_SG","REGION_JP","REGION_TW","REGION_US"]},
    {"name":"AIRPORT_GENERAL","type":"fallback","use":["Demo"]}
   ],"rules":["DOMAIN-SUFFIX,chatgpt.com,AI_FIXED_US","MATCH,AIRPORT_GENERAL"]}
  agent.CONFIG.write_text(yaml.safe_dump(self.original))
  (agent.CFG_DIR/"provider.yaml").write_text(yaml.safe_dump({"proxies":[
   {"name":"15-Singapore-Trojan","type":"trojan","password":"ANOTHER_SECRET"},
   {"name":"VIP-23-Korea","type":"anytls","password":"SECRET"}]}))
  agent.STATUS.write_text(json.dumps({"health":"ok","regional_routing":{"config_valid":True}}))
 def tearDown(self):self.tmp.cleanup()
 def test_public_status_does_not_expose_secrets(self):
  status=agent.summary()
  self.assertNotIn("SUPERSECRET",json.dumps(status))
  self.assertNotIn("ANOTHER_SECRET",json.dumps(status))
  self.assertEqual(status["nodes"],2)
 def test_subscription_masked(self):
  report=agent.subscriptions()
  self.assertEqual(report[0]["host"],"example.org")
  self.assertNotIn("SUPERSECRET",json.dumps(report))
 def test_region_node_type(self):
  x=agent.nodes()
  self.assertEqual(x[0]["region"],"SG")
  self.assertEqual(x[1]["region"],"KR")
  self.assertNotIn("password",str(x))
 def test_order_invalid_rejected(self):
  for arr in (["REGION_HK","REGION_JP","REGION_TW","REGION_US"],
              ["REGION_SG","REGION_SG","REGION_TW","REGION_US"],
              ["DIRECT"]):
   with self.assertRaises(ValueError):agent.reorder(arr)
 def test_private_url_rejected(self):
  for u in ("http://example.com/sub","https://localhost/sub","https://192.168.31.1/sub",
            "https://user:password@example.org/sub","file:///etc/passwd"):
   with self.assertRaises(ValueError):agent.validate_url(u)
 def test_safe_config_guardrails(self):
  before=agent.CONFIG.read_bytes()
  origrun=agent.run
  agent.run=lambda *a,**k: (_ for _ in ()).throw(RuntimeError("must never invoke"))
  try:
   bad=yaml.safe_load(before)
   bad["mixed-port"]=9090
   with self.assertRaises(ValueError):agent.apply(bad,"test")
   self.assertEqual(before,agent.CONFIG.read_bytes())
  finally:agent.run=origrun
 def test_atomic_maintains_owner_mode(self):
  p=self.root/"atom.txt";p.write_bytes(b"old");p.chmod(0o600)
  st=p.stat();agent.save_atomic(p,b"new")
  self.assertEqual(p.read_bytes(),b"new")
  self.assertEqual((p.stat().st_uid,p.stat().st_gid),(st.st_uid,st.st_gid))
  self.assertEqual(p.stat().st_mode&0o777,0o600)

class TestFrontend(unittest.TestCase):
 def test_javascript_syntax(self):
  p=subprocess.run(["node","--check",str(BASE/"app/app.js")],capture_output=True,text=True)
  self.assertEqual(p.returncode,0,p.stderr)
 def test_frontend_has_no_insecure_dependency(self):
  css=(BASE/"app/style.css").read_text()
  html=(BASE/"app/index.html").read_text()
  self.assertNotIn("https://",css)
  self.assertNotIn("http://",html)
  self.assertIn("autocomplete=",html)
 def test_server_auth_cookie_csp(self):
  from server import Handler
  self.assertTrue(hasattr(Handler,"csrf_ok"))
  self.assertTrue(hasattr(Handler,"session"))

if __name__=="__main__":unittest.main(verbosity=2)
