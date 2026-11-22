from pathlib import Path
import re,subprocess,sys,yaml
ROOT=Path(__file__).resolve().parents[1]
app=ROOT/"app"
required=["agent.py","subscription.py","resolve_host.py","ingress.py","server.py","app.js","style.css","index.html","favicon.svg"]
for name in required:assert (app/name).is_file(),name
src=(app/"agent.py").read_text()
frontend=(app/"app.js").read_text()
html=(app/"index.html").read_text()
assert '127.0.0.1:17896' in src
assert 'NON_HK_REGION' in src
assert 'root:f1console' in (ROOT/"INSTALL-AND-RELEASE.md").read_text()
assert 'csrf' in (app/"server.py").read_text().lower()
assert "session" in (app/"server.py").read_text().lower()
assert 'password' in html
assert "escapeHTML" in frontend
assert 'REPLACE_WITH_PUBLISHED_REVIEWED_IMAGE' in (ROOT/"hos-appstore/config.yml.template").read_text()
assert 'DO NOT INSTALL' in (ROOT/"hos-appstore/README.md").read_text()
manifest=yaml.safe_load((ROOT/"hos-appstore/config.yml.template").read_text())
assert not manifest["docker_config"]["privileged_mode"]
assert manifest["docker_config"]["network_mode"]=="bridge"
assert not manifest["docker_config"].get("devices")
assert not manifest["docker_config"].get("cap_add")
assert all("/var/run/docker.sock" not in str(p) for p in manifest["docker_config"].get("volumes",[]))
for p in app.glob("*"):
 if p.suffix in (".py",".js",".html",".css"):
  s=p.read_text()
  assert "PRIVATE_SUBSCRIPTION_URL" not in s
check=subprocess.run([sys.executable,"-m","unittest","discover","-s",str(ROOT/"tests")],cwd=ROOT,text=True,capture_output=True)
assert check.returncode==0,check.stderr
lab=subprocess.run(["bash","-n",str(ROOT/"tools/arm64_lab.sh")],capture_output=True,text=True)
assert lab.returncode==0,lab.stderr
js=subprocess.run(["node","--check",str(app/"app.js")],capture_output=True,text=True)
assert js.returncode==0,js.stderr
count=re.search(r"Ran (\d+) tests?", check.stderr).group(1)
print(f"F1_CONSOLE_RELEASE_SOURCE_GATE=PASS; unit_tests={count}; arm64_public_image=NOT_VERIFIED; native_hdp=NOT_VERIFIED; public_store=NOT_SUBMITTED")
