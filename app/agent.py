#!/usr/bin/env python3
"""Privileged local-only gateway control agent. Access restricted by Unix socket group."""
import datetime as dt, grp, json, os, pathlib, re, secrets, socket, socketserver, subprocess, tempfile, threading, time, urllib.parse
import yaml
import copy
import hashlib
import ingress
from contextlib import closing
import http.client
from subscription import Notice, fetch

BASE=pathlib.Path(os.getenv("F1_GATEWAY_HOME","/userdata/houzzkit-gateway-pilot"))
CFG_DIR=BASE/"config"; CONFIG=CFG_DIR/"config.yaml"
STATUS=BASE/"gateway-state/f1-gateway-health-status.json"
STATE=pathlib.Path(os.getenv("F1_CONSOLE_AGENT_STATE","/var/lib/f1-console-agent"))
SOCKET=os.getenv("F1_CONSOLE_AGENT_SOCKET","/run/f1-console-agent.sock")
CORE="houzzkit-gateway-pilot.service"; AGENT_LOCK=threading.Lock()
UNSYNCED_CLEANUP=None
FETCH_SLOTS=threading.BoundedSemaphore(4)
C_RE=re.compile(r"^[A-Za-z][A-Za-z0-9_-]{2,30}$")

def run(argv,timeout=30):
 return subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
def active(unit):
 try:
  result=run(["systemctl","is-active",unit],3)
  return result.returncode==0 and result.stdout.strip()=="active"
 except Exception:return False
def cfg():
 obj=yaml.safe_load(CONFIG.read_text())
 if not isinstance(obj,dict) or not isinstance(obj.get("proxy-groups"),list):raise Notice("网关配置无效")
 return obj
def sync_directory(path):
 fd=os.open(path,os.O_RDONLY)
 try:os.fsync(fd)
 finally:os.close(fd)

def save_atomic(path,content):
 fd,tmp=tempfile.mkstemp(prefix=".f1console-",dir=str(path.parent))
 try:
  with os.fdopen(fd,"wb") as f:
   if path.parent==STATE:
    os.fchown(fd,os.geteuid(),os.getegid())
   elif path.exists():
    oldstat=path.stat()
    os.fchown(fd,oldstat.st_uid,oldstat.st_gid)
   elif path.parent==CFG_DIR:
    owned=CONFIG.stat()
    os.fchown(fd,owned.st_uid,owned.st_gid)
   f.write(content);f.flush();os.fsync(f.fileno())
  os.replace(tmp,path)
  sync_directory(path.parent)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
def cache_nodes(c,name):
 pr=c.get("proxy-providers",{}).get(name,{})
 path=pr.get("path")
 if not isinstance(path,str):return []
 p=(CFG_DIR/path).resolve()
 if not p.is_relative_to(CFG_DIR.resolve()):return []
 try:
  if not p.is_file():return []
  with p.open("rb") as source:body=source.read(2_000_001)
  if len(body)>2_000_000:return []
  val=yaml.safe_load(body)
  items=val.get("proxies") if isinstance(val,dict) else None
  return items[:1200] if isinstance(items,list) else []
 except Exception:return []
def region(name):
 t=name.lower()
 for k,words in (("HK",("hong kong","香港")),("SG",("singapore","新加坡")),("JP",("japan","日本")),("TW",("taiwan","台湾")),("KR",("korea","韩国")),("US",("united states","美国"))):
  if any(w in t for w in words):return k
 return "OTHER"
def json_controller(path,timeout=4):
 c=cfg()
 if c.get("external-controller")!="127.0.0.1:17896":raise Notice("控制接口未启用")
 headers={"Authorization":"Bearer "+str(c.get("secret",""))}
 with closing(http.client.HTTPConnection("127.0.0.1",17896,timeout=timeout)) as conn:
  conn.request("GET",path,headers=headers)
  with conn.getresponse() as response:
   if response.status!=200:raise Notice("控制接口读取失败")
   return json.load(response)


def summary():
 c=cfg()
 try:h=json.loads(STATUS.read_text())
 except Exception:h={}
 names={g["name"]:g for g in c["proxy-groups"]}
 selected={}
 if c.get("external-controller")=="127.0.0.1:17896":
  for g in ("AI_FIXED_US","NON_HK_REGION","AIRPORT_GENERAL"):
   try:selected[g]=json_controller("/proxies/"+urllib.parse.quote(g),2).get("now","—")
   except Exception:selected[g]="未知"
 return {"version":"0.2.0","gateway":active(CORE),"udp":active("f1-udp-ebpf.service"),
   "docker":active("docker.service"),"health":h.get("health","unknown"),"checked_at":h.get("checked_at"),
   "errors_5m":h.get("mihomo_connect_errors_last_5m"),"containers":h.get("docker_running_count"),
   "region_ok":h.get("regional_routing",{}).get("config_valid"),
   "mode":"本地网关管理；接入方式需在设备上核验","groups":[{"name":n,"type":g.get("type"),"now":selected.get(n,"自动")} for n,g in names.items()],
   "regions":names.get("NON_HK_REGION",{}).get("proxies",[]),"providers":len(c.get("proxy-providers",{})),
   "nodes":sum(len(cache_nodes(c,n)) for n in c.get("proxy-providers",{})),
   "recovery_pending":has_pending(),"controller":c.get("external-controller")=="127.0.0.1:17896"}
def saved_subscriptions():
 path=STATE/"subscriptions.json"
 if not path.exists():return {}
 return json.loads(path.read_bytes())

def subscriptions():
 with AGENT_LOCK:
  c=cfg();out=[]
  for n,p in c.get("proxy-providers",{}).items():
   used=[g["name"] for g in c["proxy-groups"] if n in g.get("use",[]) or
         g.get("include-all") or g.get("include-all-providers")]
   host=urllib.parse.urlsplit(p.get("url","")).hostname or "本地文件"
   out.append({"name":n,"host":host,"count":len(cache_nodes(c,n)),"used_by":used,
               "managed":False,"locked":True})
  for n,item in saved_subscriptions().items():
   out.append({"name":n,"host":item["host"],"count":item["count"],"usage":item.get("usage"),
               "used_by":[],"managed":True,"locked":False})
  return out
def nodes():
 c=cfg();out=[]
 for n in c.get("proxy-providers",{}):
  for p in cache_nodes(c,n):
   if isinstance(p,dict) and isinstance(p.get("name"),str):
    name=p["name"][:128]
    protocol=p.get("type")
    out.append({"name":name,"provider":n,"region":region(name),"protocol":protocol if isinstance(protocol,str) and re.fullmatch(r"[A-Za-z0-9-]{1,24}",protocol) else "未知"})
    if len(out)>=1200:return out
 return out
def policy():
 c=cfg();d={x["name"]:x for x in c["proxy-groups"]}
 return {"regions":d.get("NON_HK_REGION",{}).get("proxies",[]),
         "rules":[{"match":r.split(",")[1],"group":r.rsplit(",",1)[-1]} for r in c["rules"] if r.endswith((",NON_HK_REGION",",AI_FIXED_US"))]}
def node_test(name):
 if not isinstance(name,str) or name not in {n["name"] for n in nodes()}:raise Notice("节点不存在")
 try:
  cache_match=next((n for n in nodes() if n["name"]==name),None)
  if not cache_match:raise Notice("节点不存在")
  provider=cache_match["provider"]
  path="/providers/proxies/"+urllib.parse.quote(provider,safe="")+"/"+urllib.parse.quote(name,safe="")+"/healthcheck?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=6500"
  data=json_controller(path,11)
  ms=data.get("delay");return {"name":name,"delay":ms,"online":isinstance(ms,int) and 0<ms<6500}
 except Exception:return {"name":name,"online":False,"delay":None}
def validate_url(u):
 return fetch(u)["count"]

def require_running(config):
 port=config.get("mixed-port")
 if type(port) is not int or not 1<=port<=65535:raise Notice("缺少本机代理端口")
 controller=str(config.get("external-controller","")).rpartition(":")[2]
 if controller==str(port):raise Notice("控制接口与代理入口端口冲突")
 deadline=time.monotonic()+13
 while (remaining:=deadline-time.monotonic())>0:
  try:
   result=run(["systemctl","is-active",CORE],min(3,remaining))
   if result.returncode==0 and result.stdout.strip()=="active":
    remaining=deadline-time.monotonic()
    if remaining<=0:break
    proc=run(["systemctl","show",CORE,"--property=MainPID","--value"],min(2,remaining))
    pid=proc.stdout.strip()
    hosts=None
    if proc.returncode==0 and pid.isascii() and pid.isdigit() and int(pid)>0:
     hosts=ingress.owned_listeners(pathlib.Path("/proc")/pid,port)
    if hosts is None:hosts=ingress.configured_hosts(config)
    for host in hosts:
     remaining=deadline-time.monotonic()
     if remaining<=0:break
     try:
      with socket.create_connection((host,port),timeout=min(2,remaining)):return
     except OSError:pass
  except (OSError,subprocess.TimeoutExpired):pass
  time.sleep(max(0,min(0.7,deadline-time.monotonic())))
 raise Notice("核心服务或本机代理入口未就绪")

def restart_checked(config):
 if run(["systemctl","restart",CORE],35).returncode:raise Notice("核心服务重启失败")
 require_running(config)

def digest(data):
 return hashlib.sha256(data).hexdigest()

def has_pending():
 return UNSYNCED_CLEANUP is not None or (STATE/"pending.json").exists()

def clear_pending():
 (STATE/"pending.json").unlink(missing_ok=True)
 sync_directory(STATE)

def finish_transaction(outcome,expected_digest):
 global UNSYNCED_CLEANUP
 applied=outcome=="applied"
 message="已应用，已确认代理入口" if applied else "已恢复旧配置并确认代理入口"
 try:clear_pending()
 except OSError:
  # unlink may have succeeded while directory fsync failed. Retry the barrier
  # before another mutation, even if the receipt is no longer visible.
  UNSYNCED_CLEANUP=(outcome,expected_digest)
  return {"applied":applied,"outcome":outcome,"cleanup_pending":True,"message":message+"；收据待清理，可在系统设置中重试"}
 UNSYNCED_CLEANUP=None
 return {"applied":applied,"outcome":outcome,"cleanup_pending":False,"message":message}

def recover_pending():
 """Caller holds the mutation lock or runs before accepting socket requests."""
 path=STATE/"pending.json"
 if not path.exists():
  if UNSYNCED_CLEANUP:
   outcome,known=UNSYNCED_CLEANUP
   current=CONFIG.read_bytes()
   if digest(current)!=known:raise Notice("清理期间配置已被外部修改")
   require_running(yaml.safe_load(current))
   if CONFIG.read_bytes()!=current:raise Notice("核验期间配置已被外部修改")
   return finish_transaction(outcome,known)
  return {"applied":False,"outcome":"unchanged","cleanup_pending":False,"message":"无待确认变更"}
 receipt=json.loads(path.read_bytes())
 backup=receipt["backup"]
 phase=receipt.get("phase","legacy")
 if (not re.fullmatch(r"backup-[0-9]{14}-[0-9a-f]{6}\.yaml",backup) or
     phase not in ("legacy","prepared","activating","restoring","restored") or
     any(not re.fullmatch("[0-9a-f]{64}",receipt[key]) for key in ("old","new")) or
     receipt["old"]==receipt["new"]):raise Notice("恢复收据无效")
 before=(STATE/backup).read_bytes()
 if digest(before)!=receipt["old"]:raise Notice("恢复备份校验失败")
 current=CONFIG.read_bytes()
 if digest(current) not in (receipt["old"],receipt["new"]):
  raise Notice("发现外部配置变动，已停止自动写入")
 marker=STATE/"last-change.json"
 commit=json.loads(marker.read_bytes()) if marker.exists() else {}
 if commit.get("backup")==backup:
  if (digest(current)!=receipt["new"] or
      (phase not in ("legacy","activating")) or
      (("new" in commit or phase!="legacy") and commit.get("new")!=receipt["new"])):
   raise Notice("提交记录与当前配置不一致")
  require_running(yaml.safe_load(current))
  expected=current
  outcome="applied"
 else:
  old=yaml.safe_load(before)
  if current==before and phase in ("prepared","restored"):
   try:require_running(old)
   except Notice:
    if CONFIG.read_bytes()!=before:raise Notice("核验期间配置已被外部修改")
    restart_checked(old)
  else:
   # An old file after interrupted rollback does not prove which generation
   # the running process loaded. Keep that ambiguity across further crashes.
   if phase=="restored":raise Notice("已恢复记录与当前配置不一致")
   if phase!="restoring":
    receipt["phase"]="restoring"
    save_atomic(path,json.dumps(receipt).encode())
   if CONFIG.read_bytes()!=current:raise Notice("恢复期间配置已被外部修改")
   if current!=before:save_atomic(CONFIG,before)
   restart_checked(old)
   receipt["phase"]="restored"
   save_atomic(path,json.dumps(receipt).encode())
  expected=before
  outcome="rolled_back"
 if CONFIG.read_bytes()!=expected:raise Notice("恢复期间配置已被外部修改")
 return finish_transaction(outcome,digest(expected))

def retry_recovery():
 with AGENT_LOCK:return recover_pending()

def apply(new,reason):
 if has_pending():raise Notice("上次配置变更等待恢复，请检查代理服务")
 before=CONFIG.read_bytes();old=yaml.safe_load(before)
 for key in ("mixed-port","redir-port","tproxy-port","dns"):
  if new.get(key)!=old.get(key):raise Notice("为保护家庭网络禁止修改网关入口/DNS")
 gs={g["name"]:g for g in new["proxy-groups"]}
 if (gs.get("AI_FIXED_US",{}).get("proxies")!=["AI-US-DEDICATED"] or
     set(gs.get("NON_HK_REGION",{}).get("proxies",[]))!={"REGION_SG","REGION_JP","REGION_TW","REGION_US"} or
     new["rules"][-1]!="MATCH,AIRPORT_GENERAL"):
  raise Notice("AI专线/非香港区域安全策略不完整")
 expected=copy.deepcopy(old)
 if reason=="region_priority":
  changed=[g for g in expected["proxy-groups"] if g["name"]=="NON_HK_REGION"]
  order=gs["NON_HK_REGION"]["proxies"]
  if len(changed)!=1 or len(order)!=4:raise Notice("地区分组配置异常")
  changed[0]["proxies"]=order
 elif reason=="controller_loopback" and not old.get("external-controller"):
  expected.update({"external-controller":"127.0.0.1:17896","secret":new.get("secret")})
 else:raise Notice("不支持此配置变更")
 if new!=expected:raise Notice("变更超出授权配置范围")
 if old==new:return {"applied":False,"message":"没有配置变更"}
 data=yaml.safe_dump(new,sort_keys=False,allow_unicode=True).encode()
 if data==before:return {"applied":False,"message":"没有配置变更"}
 stamp=dt.datetime.now().strftime("%Y%m%d%H%M%S")+"-"+secrets.token_hex(3)
 STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
 stage=CFG_DIR/(".console-"+secrets.token_hex(4)+".yaml");save_atomic(stage,data)
 try:
  probe=run([str(BASE/"bin/mihomo"),"-t","-d",str(CFG_DIR),"-f",str(stage)],24)
  if probe.returncode:raise Notice("Mihomo 配置预检未通过；未修改正式配置")
  stage.unlink()
  if CONFIG.read_bytes()!=before:raise Notice("预检期间配置已被外部修改")
  backup="backup-"+stamp+".yaml"
  save_atomic(STATE/backup,before)
  receipt={"backup":backup,"old":digest(before),"new":digest(data),"phase":"prepared"}
  save_atomic(STATE/"pending.json",json.dumps(receipt).encode())
  if CONFIG.read_bytes()!=before:raise Notice("发现外部配置变动，已停止自动写入")
  save_atomic(CONFIG,data)
  receipt["phase"]="activating"
  save_atomic(STATE/"pending.json",json.dumps(receipt).encode())
  restart_checked(new)
  if CONFIG.read_bytes()!=data:raise Notice("确认期间配置已被外部修改")
  save_atomic(STATE/"last-change.json",json.dumps({"action":reason,"time":stamp,"backup":backup,"new":receipt["new"]}).encode())
  if CONFIG.read_bytes()!=data:raise Notice("提交时发现外部配置变动")
  return finish_transaction("applied",receipt["new"])
 except Exception:
  if (STATE/"pending.json").exists():
   try:result=recover_pending()
   except Exception:
    raise Notice("自动恢复未能确认；请检查核心服务和私有备份") from None
   if result["applied"]:return result
   raise Notice("应用失败；"+result["message"]) from None
  raise
 finally:stage.unlink(missing_ok=True)
def subscription_edit(name,url,update):
 if not isinstance(name,str) or not C_RE.fullmatch(name):raise Notice("订阅名需3–31位英文/数字/下划线")
 def checked_catalog():
  saved=saved_subscriptions()
  existing=cfg().get("proxy-providers",{})
  if name in existing:raise Notice("运行配置中的订阅受保护")
  if (name in saved)!=update:raise Notice("订阅名称已存在或不存在")
  if not update and len(existing)+len(saved)>=10:raise Notice("最多支持10个订阅")
  if any(n!=name and item["url"]==url for n,item in saved.items()) or any(
     provider.get("url")==url for provider in existing.values()):
   raise Notice("该地址已有订阅")
  return saved
 with AGENT_LOCK:
  previous=checked_catalog().get(name)
 if not FETCH_SLOTS.acquire(blocking=False):raise Notice("订阅校验繁忙，请稍后重试")
 try:info=fetch(url)
 finally:FETCH_SLOTS.release()
 with AGENT_LOCK:
  saved=checked_catalog()
  if saved.get(name)!=previous:raise Notice("订阅已变更，请刷新后再试")
  saved[name]={**info,"url":url}
  write_saved(saved)
  return {"name":name,"validated_nodes":info["count"],"enabled":False}

def write_saved(saved):
 STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
 save_atomic(STATE/"subscriptions.json",json.dumps(saved).encode())

def subscription_delete(name):
 if not isinstance(name,str) or not C_RE.fullmatch(name):raise Notice("订阅名不合法")
 with AGENT_LOCK:
  saved=saved_subscriptions()
  if name in cfg().get("proxy-providers",{}):raise Notice("运行配置中的订阅受保护")
  if name not in saved:raise Notice("订阅不存在")
  del saved[name]
  write_saved(saved)
  return {"deleted":True}

def reorder(order):
 valid={"REGION_SG","REGION_JP","REGION_TW","REGION_US"}
 if not isinstance(order,list) or len(order)!=4 or set(order)!=valid:raise Notice("只能使用SG/JP/TW/US四个地区")
 with AGENT_LOCK:
  c=cfg()
  for group in c["proxy-groups"]:
   if group["name"]=="NON_HK_REGION":
    group["proxies"]=order
    return apply(c,"region_priority")
  raise Notice("非香港分组不存在")
def controller_activate():
 with AGENT_LOCK:
  c=cfg()
  if c.get("external-controller")=="127.0.0.1:17896" and c.get("secret"):return {"enabled":True}
  if c.get("external-controller"):raise Notice("原有控制端口占用，无法自动开启")
  c["external-controller"]="127.0.0.1:17896";c["secret"]=secrets.token_urlsafe(32)
  return {"enabled":True,**apply(c,"controller_loopback")}
METHODS={"recovery_retry":lambda a:retry_recovery(),"summary":lambda a:summary(),"subscriptions":lambda a:subscriptions(),"nodes":lambda a:nodes(),
 "policy":lambda a:policy(),"test_node":lambda a:node_test(a.get("name")),
 "subscription_add":lambda a:subscription_edit(a.get("name"),a.get("url"),False),
 "subscription_update":lambda a:subscription_edit(a.get("name"),a.get("url"),True),
 "subscription_delete":lambda a:subscription_delete(a.get("name")),
 "region_reorder":lambda a:reorder(a.get("order")),
 "controller_activate":lambda a:controller_activate()}
class Handler(socketserver.StreamRequestHandler):
 def handle(self):
  self.connection.settimeout(80)
  try:
   raw=self.rfile.readline(65537)
   if len(raw)>65536:raise Notice("请求太大")
   request=json.loads(raw)
   if not isinstance(request,dict) or request.get("action") not in METHODS:raise Notice("不支持的操作")
   result={"ok":True,"data":METHODS[request["action"]](request)}
  except Exception as e:
   print("F1_AGENT_REQUEST_FAIL_TYPE="+type(e).__name__,flush=True)
   error=str(e) if isinstance(e,Notice) else "操作失败；请检查配置和服务状态"
   result={"ok":False,"error":error[:150]}
  self.wfile.write((json.dumps(result,ensure_ascii=False)+"\n").encode())
class Server(socketserver.ThreadingUnixStreamServer):daemon_threads=True
def main():
 STATE.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(STATE,0o700)
 try:recover_pending()
 except Exception:print("上次配置变更等待人工核验，配置写入已锁定",flush=True)
 pathlib.Path(SOCKET).unlink(missing_ok=True)
 with Server(SOCKET,Handler) as srv:
  os.chown(SOCKET,0,grp.getgrnam("f1console").gr_gid);os.chmod(SOCKET,0o660)
  srv.serve_forever()
if __name__=="__main__":main()
