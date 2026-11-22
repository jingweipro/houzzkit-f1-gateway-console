const el = id => document.getElementById(id);
let csrf;
async function refresh() {
  const response = await fetch('/status');
  el('panel').hidden = !response.ok;
  el('login').hidden = response.ok;
  el('credential').textContent = '';
  if (!response.ok) return;
  const s = await response.json();
  csrf = s.csrf;
  el('status').textContent = `已保存 ${s.saved} 个节点，启用配置 ${s.active} 个。代理认证端口${s.listening ? '监听中' : '未就绪'}。`;
  el('credential').textContent = s.password;
}
async function act(path, body) {
  try {
    const res = await fetch('/'+path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({...body, csrf})});
    el('message').textContent = res.ok ? '操作完成' : '操作失败，请检查登录、订阅格式或核心状态';
    await refresh();
  } catch { el('message').textContent = '连接失败，请刷新核对状态'; }
}
el('login').onsubmit = e => { e.preventDefault(); act('login',{password:el('pw').value}); el('pw').value=''; };
el('save').onsubmit = e => { e.preventDefault(); act('save',{url:el('url').value}); el('url').value=''; };
for (const id of ['enable','disable','logout']) el(id).onclick = () => act(id,{});
el('refresh').onclick = refresh;
refresh();
