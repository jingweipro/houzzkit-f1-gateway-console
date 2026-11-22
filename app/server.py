#!/usr/bin/env python3
"""F1 Console unprivileged authenticated LAN UI. No Docker socket or sudo."""
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from http.cookies import SimpleCookie
import hashlib,hmac,json,os,pathlib,secrets,socket,threading,time,urllib.parse

HERE=pathlib.Path(__file__).resolve().parent
BIND=os.getenv("F1_CONSOLE_BIND","127.0.0.1")
PORT=int(os.getenv("F1_CONSOLE_PORT","17680"))
STATE=pathlib.Path(os.getenv("F1_CONSOLE_UI_STATE","/var/lib/f1-console-ui"))
SOCKET=os.getenv("F1_CONSOLE_AGENT_SOCKET","/run/f1-console-agent.sock")
SESSIONS={};LOGIN_ATTEMPTS={};LOCK=threading.RLock()
MAX_BODY=8192
def hash_password(password,salt):
 return hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=2**14,r=8,p=1).hex()
def credential_path():return STATE/"auth.json"
def make_credential(password):
 salt=secrets.token_hex(16)
 return {"salt":salt,"key":hash_password(password,salt)}
def verify_password(password):
 try:c=json.loads(credential_path().read_text())
 except Exception:return False
 return hmac.compare_digest(hash_password(password,c["salt"]),c["key"])
def initialize():
 STATE.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(STATE,0o700)
 if credential_path().exists():return
 pw=secrets.token_urlsafe(18)
 auth=make_credential(pw)
 for name,payload in (("auth.json",json.dumps(auth)),("INITIAL-PASSWORD.txt",pw+"\n")):
  path=STATE/name
  flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
  fd=os.open(path,flags,0o600)
  with os.fdopen(fd,"w") as f:f.write(payload)
def send_agent(action,**params):
 data=json.dumps({"action":action,**params},ensure_ascii=False).encode()+b"\n"
 if len(data)>60000:raise ValueError("请求过大")
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
  client.settimeout(150);client.connect(SOCKET);client.sendall(data)
  reply=b""
  while not reply.endswith(b"\n") and len(reply)<2_000_000:
   buf=client.recv(16384)
   if not buf:break
   reply+=buf
 result=json.loads(reply)
 if not result.get("ok"):raise ValueError(result.get("error","操作失败"))
 return result["data"]
def prune_sessions():
 now=time.monotonic()
 for token,auth in list(SESSIONS.items()):
  if now-auth["seen"]>3600:SESSIONS.pop(token,None)
 for ip,(count,last) in list(LOGIN_ATTEMPTS.items()):
  if now-last>900:LOGIN_ATTEMPTS.pop(ip,None)

class Handler(BaseHTTPRequestHandler):
 protocol_version="HTTP/1.1"
 def log_message(self, fmt,*args):
  # no URL, sensitive values or full request paths in logs
  pass
 def headers_base(self,content_type,content_len):
  self.send_header("Content-Type",content_type)
  self.send_header("Content-Length",str(content_len))
  self.send_header("Cache-Control","private, no-store, max-age=0")
  self.send_header("X-Content-Type-Options","nosniff")
  self.send_header("X-Frame-Options","DENY")
  self.send_header("Referrer-Policy","no-referrer")
  self.send_header("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
 def reply(self,body,status=200,mime="application/json; charset=utf-8",cookie=None):
  if not isinstance(body,bytes):
   body=json.dumps(body,ensure_ascii=False).encode()
  self.send_response(status)
  self.headers_base(mime,len(body))
  if cookie:self.send_header("Set-Cookie",cookie)
  self.end_headers()
  if self.command!="HEAD":self.wfile.write(body)
 def error(self,message,status=400):
  self.reply({"error":str(message)[:130]},status)
 def client_ip(self):return self.client_address[0]
 def session(self):
  raw=self.headers.get("Cookie","")
  if len(raw)>600:return None
  try:
   c=SimpleCookie();c.load(raw)
   token=c["F1_SESSION"].value if "F1_SESSION" in c else ""
  except Exception:return None
  with LOCK:
   prune_sessions()
   auth=SESSIONS.get(token)
   if auth:auth["seen"]=time.monotonic()
   return auth
 def csrf_ok(self,auth):
  host=self.headers.get("Host","")
  origin=self.headers.get("Origin","")
  if not host or origin!="http://"+host:return False
  return bool(auth and hmac.compare_digest(self.headers.get("X-CSRF-Token",""),auth["csrf"]))
 def json_body(self):
  try:n=int(self.headers.get("Content-Length","0"))
  except Exception:raise ValueError("请求大小无效")
  if n<=0 or n>MAX_BODY:raise ValueError("请求长度不合法")
  try:obj=json.loads(self.rfile.read(n))
  except ValueError:raise ValueError("JSON 格式无效") from None
  if not isinstance(obj,dict):raise ValueError("只接受 JSON 对象")
  return obj
 def do_GET(self):
  path=urllib.parse.urlsplit(self.path).path
  if path in ("/","/index.html"):
   return self.reply((HERE/"index.html").read_bytes(),200,"text/html; charset=utf-8")
  if path=="/app.js":return self.reply((HERE/"app.js").read_bytes(),200,"text/javascript; charset=utf-8")
  if path=="/style.css":return self.reply((HERE/"style.css").read_bytes(),200,"text/css; charset=utf-8")
  if path=="/favicon.svg":return self.reply((HERE/"favicon.svg").read_bytes(),200,"image/svg+xml")
  if path=="/api/session":
   auth=self.session()
   return self.reply({"authenticated":bool(auth),"csrf":auth["csrf"] if auth else None,"version":"0.2.0"})
  auth=self.session()
  if not auth:return self.error("需要登录",401)
  mapping={"/api/summary":"summary","/api/subscriptions":"subscriptions","/api/nodes":"nodes","/api/policy":"policy"}
  if path in mapping:
   try:return self.reply(send_agent(mapping[path]))
   except Exception:return self.error("网关数据暂不可用",503)
  return self.error("不存在",404)
 def do_POST(self):
  path=urllib.parse.urlsplit(self.path).path
  if path=="/api/login":
   try:
    data=self.json_body();ip=self.client_ip()
    with LOCK:
     prune_sessions()
     count,last=LOGIN_ATTEMPTS.get(ip,(0,0))
     if count>=7 and time.monotonic()-last<900:return self.error("登录尝试过多，请15分钟后重试",429)
     LOGIN_ATTEMPTS[ip]=(count+1,time.monotonic())
    password=data.get("password","")
    if not isinstance(password,str) or len(password)>200 or not verify_password(password):
     return self.error("密码不正确",401)
    token=secrets.token_urlsafe(32);auth={"csrf":secrets.token_urlsafe(28),"seen":time.monotonic()}
    with LOCK:SESSIONS[token]=auth;LOGIN_ATTEMPTS.pop(ip,None)
    return self.reply({"authenticated":True,"csrf":auth["csrf"]},
      cookie="F1_SESSION="+token+"; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600")
   except Exception:return self.error("登录失败",400)
  auth=self.session()
  if not auth:return self.error("请先登录",401)
  if not self.csrf_ok(auth):return self.error("安全校验失败",403)
  if path=="/api/logout":
   raw=self.headers.get("Cookie","")
   try:
    c=SimpleCookie();c.load(raw)
    token=c["F1_SESSION"].value if "F1_SESSION" in c else ""
   except Exception:token=""
   with LOCK:SESSIONS.pop(token,None)
   return self.reply({"ok":True},cookie="F1_SESSION=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
  if path=="/api/password":
   try:
    b=self.json_body()
    if not verify_password(b.get("old","")):return self.error("旧密码不正确",401)
    new=b.get("new","")
    if not isinstance(new,str) or len(new)<12 or len(new)>200:raise ValueError("新密码至少12位")
    dest=credential_path()
    temp=STATE/(".auth-"+secrets.token_hex(8))
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"w") as f:json.dump(make_credential(new),f)
    os.replace(temp,dest)
    (STATE/"INITIAL-PASSWORD.txt").unlink(missing_ok=True)
    with LOCK:SESSIONS.clear()
    return self.reply({"changed":True},cookie="F1_SESSION=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
   except ValueError as e:return self.error(e,400)
   except Exception:return self.error("更新失败",500)
  actions={"/api/recovery/retry":"recovery_retry","/api/test-node":"test_node","/api/subscription/add":"subscription_add",
           "/api/subscription/update":"subscription_update",
           "/api/subscription/delete":"subscription_delete",
           "/api/region-order":"region_reorder"}
  if path not in actions:return self.error("不存在",404)
  with LOCK:
   now=time.monotonic()
   recent=[t for t in auth.get("operations",[]) if now-t<60]
   if len(recent)>=12:return self.error("操作频繁，请稍后重试",429)
   auth["operations"]=recent+[now]
  try:
   b=self.json_body()
   params={k:b[k] for k in ("name","url","order") if k in b}
   return self.reply(send_agent(actions[path],**params))
  except ValueError as e:return self.error(e,400)
  except Exception:return self.error("操作未完成；请核对健康状态",503)
 def do_HEAD(self):self.do_GET()

def main():
 initialize()
 httpd=ThreadingHTTPServer((BIND,PORT),Handler)
 httpd.daemon_threads=True
 print("F1_CONSOLE_UI_LISTEN="+BIND+":"+str(PORT),flush=True)
 httpd.serve_forever()
if __name__=="__main__":main()
