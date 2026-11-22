"use strict";
const $=id=>document.getElementById(id);
const escapeHTML=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const cn={REGION_SG:"新加坡",REGION_JP:"日本",REGION_TW:"台湾",REGION_US:"美国"};
const flag={SG:"🇸🇬",JP:"🇯🇵",TW:"🇹🇼",US:"🇺🇸",HK:"🇭🇰",KR:"🇰🇷",OTHER:"🌐"};
const names={overview:"运行总览",subscriptions:"机场订阅",routing:"地区分流",nodes:"节点诊断",settings:"系统设置"};
let csrf="",overview={},subs=[],nodelist=[],policy={},regionOrder=[],view="overview";
async function api(path,method="GET",body=null){
 const opts={method,credentials:"same-origin",cache:"no-store",headers:{}};
 if(method!=="GET"){opts.headers["Content-Type"]="application/json";opts.headers["X-CSRF-Token"]=csrf;opts.body=JSON.stringify(body||{});}
 const res=await fetch(path,opts);let data;
 try{data=await res.json()}catch(_){throw Error("网关响应格式异常");}
 if(!res.ok)throw Error(data.error||"操作失败");
 return data;
}
function toast(msg,error=false){
 const n=$("alert");n.textContent=msg;n.className="toast"+(error?" error":"");
 clearTimeout(toast.timer);toast.timer=setTimeout(()=>n.classList.add("hidden"),4700);
}
function showApp(ok){
 $("login").classList.toggle("hidden",ok);$("app").classList.toggle("hidden",!ok);
 if(ok)openView("overview");
}
function dateText(v){
 if(!v)return"暂无数据";
 const d=new Date(v);
 return Number.isFinite(+d)?d.toLocaleString("zh-CN",{hour12:false}):String(v).slice(0,24);
}
async function login(ev){
 ev.preventDefault();const el=$("login-password");
 const button=$("login-form").querySelector("button");button.disabled=true;
 try{const x=await api("/api/login","POST",{password:el.value});csrf=x.csrf;el.value="";showApp(true);await refreshAll();toast("欢迎回来，网关控制台已连接");}
 catch(e){toast(e.message,true)}
 finally{button.disabled=false}
}
async function logout(){
 try{await api("/api/logout","POST",{})}catch(_){}
 csrf="";showApp(false);$("login-password").value="";
}
async function refreshAll(){
 try{
  const r=await Promise.all([api("/api/summary"),api("/api/subscriptions"),api("/api/nodes"),api("/api/policy")]);
  [overview,subs,nodelist,policy]=r;
  regionOrder=(policy.regions||[]).slice();
  renderSummary();renderSubscriptions();renderRegions();renderNodes();renderSettings();return true;
 }catch(e){toast("数据刷新失败："+e.message,true);return false}
}
async function refreshSummary(){
 try{overview=await api("/api/summary");renderSummary();renderSettings()}catch(_){}
}
function openView(v){
 if(!names[v])return;
 view=v;
 for(const name of Object.keys(names))$(name).classList.toggle("hidden",name!==v);
 for(const btn of document.querySelectorAll("#nav .nav-item"))btn.classList.toggle("active",btn.dataset.view===v);
 $("breadcrumb").textContent=names[v];
 if(v==="nodes")renderNodes();
 window.scrollTo({top:0,behavior:"smooth"});
}
function renderSummary(){
 const healthy=overview.health==="ok"&&overview.gateway&&overview.udp;
 const warning=overview.gateway&&overview.udp&&!healthy;
 $("hero-health").textContent=healthy?"运行正常":warning?"需要关注":"连接异常";
 $("health-note").textContent=healthy?"全部关键服务正在运行，智能分流规则已加载。":warning?"网关核心在线，但监控检测到需要检查的告警。":"管理端无法确认核心运行状态，请检查 F1 服务。";
 const pill=$("status-pill");pill.className="pill "+(healthy?"":warning?"warning":"error");
 pill.innerHTML='<span class="pulse"></span> '+(healthy?"网关在线":warning?"存在告警":"网关异常");
 $("count-nodes").textContent=overview.nodes??"—";
 $("count-providers").textContent=overview.providers??"—";
 $("count-containers").textContent=overview.containers??"—";
 $("side-state").textContent=healthy?"正常运行":warning?"运行中 · 有告警":"需要检查";
 $("last-check").textContent="最近核验："+dateText(overview.checked_at);
 const selects=Object.fromEntries((overview.groups||[]).map(x=>[x.name,x.now]));
 $("ai-selected").textContent=selects.AI_FIXED_US||"未知";
 $("region-selected").textContent=(regionOrder||[]).map(k=>k.replace("REGION_","")).join(" → ");
 $("general-selected").textContent=selects.AIRPORT_GENERAL||"未知";
 const items=[["Mihomo 代理核心","规则引擎和互联网分流",!!overview.gateway],
 ["UDP 透明转发","F1 eBPF 网络转发",!!overview.udp],
 ["智能区域规则","非香港地区分流安全检查",overview.region_ok===true],
 ["Docker 生态","Home Assistant、Matter 等容器运行环境",!!overview.docker],
 ["连接错误统计","过去5分钟记录 "+(overview.errors_5m??"—")+" 次错误",overview.errors_5m===0]];
 $("service-list").innerHTML=items.map(([name,description,ok],i)=>'<div class="service-item"><div class="service-symbol">'+["◈","⇄","◎","▣","▥"][i]+'</div><div class="service-name"><b>'+escapeHTML(name)+'</b><small>'+escapeHTML(description)+'</small></div><span class="'+(ok?"state-ok":"state-warn")+'">'+(ok?"正常":"注意")+'</span></div>').join("");
}
function renderSubscriptions(){
 $("subs-count").textContent=subs.length+" 份订阅";
 const query=$("sub-search").value.trim().toLowerCase();
 const shown=subs.filter(s=>(s.name+" "+s.host).toLowerCase().includes(query));
 $("sub-list").innerHTML=shown.map(s=>{
  const name=escapeHTML(s.name);
  const groups=(s.used_by||[]).map(escapeHTML).join("、");
  const status=s.managed?"已保存，尚未启用":groups?"已配置分组":"运行配置中";
  const controls=s.managed?`<div class="sub-actions">
    <button class="btn small" data-sub-update="${name}">更换地址</button>
    <button class="btn small danger" data-sub-delete="${name}">删除</button>
    <button class="btn small" disabled>启用到普通机场组（尚未开放）</button></div>
    <form class="sub-update-form hidden" data-form-update="${name}">
    <label>新订阅 HTTPS 地址<input type="password" name="url" autocomplete="off" maxlength="3000" required></label>
    <button class="btn primary small">验证并替换</button></form>`:"<small>运行配置受保护，仅供查看</small>";
  const usage=s.usage?`<details><summary>查看服务商用量</summary>上次校验时：上传 ${s.usage.upload} 字节，下载 ${s.usage.download} 字节，总额度 ${s.usage.total} 字节。</details>`:"";
  return `<div class="sub-item"><div class="sub-top"><b>${name}</b><span class="tag">${status}</span></div>
    <div class="sub-host">${escapeHTML(s.host)}</div><div class="sub-meta">${escapeHTML(s.count)} 个节点 ${groups?" · "+groups:""}</div>${usage}${controls}</div>`;
 }).join("")||(subs.length?"没有匹配的订阅":"暂无订阅，请填写名称和订阅地址。");
}
function renderRegions(){
 $("region-list").innerHTML=regionOrder.map((key,i)=>'<div class="region-line"><span class="region-rank">'+String(i+1).padStart(2,"0")+'</span><div class="region-main"><b>'+escapeHTML(cn[key]||key)+'</b><small>'+escapeHTML(key)+' · '+(i===0?"优先地区":i===3?"最终备用":"故障备用")+'</small></div><div class="region-move"><button class="tiny-btn" title="上移" data-move="'+i+':-1" '+(i===0?"disabled":"")+'>↑</button><button class="tiny-btn" title="下移" data-move="'+i+':1" '+(i===regionOrder.length-1?"disabled":"")+'>↓</button></div></div>').join("");
 $("policy-list").innerHTML=(policy.rules||[]).map(r=>'<div class="policy-item"><span>'+escapeHTML(r.match)+'</span><b>'+escapeHTML(r.group==="NON_HK_REGION"?"非香港地区":"独立美国线路")+'</b></div>').join("");
}
function renderNodes(){
 const q=$("node-search").value.trim().toLowerCase(),r=$("node-region-filter").value;
 const shown=nodelist.filter(n=>(!r||n.region===r)&&(!q||n.name.toLowerCase().includes(q))).slice(0,150);
 $("node-table").innerHTML=shown.length?shown.map(n=>'<tr><td class="node-cell">'+escapeHTML(n.name)+'</td><td><span class="node-region">'+escapeHTML(flag[n.region]||"🌐")+' '+escapeHTML(n.region)+'</span></td><td>'+escapeHTML(n.protocol)+'</td><td>'+escapeHTML(n.provider)+'</td><td><button class="btn small" data-test-node="'+escapeHTML(n.name)+'">测试连接</button></td></tr>').join(""):'<tr><td colspan="5">无符合条件的节点</td></tr>';
 $("node-foot").textContent="匹配 "+nodelist.filter(n=>(!r||n.region===r)&&(!q||n.name.toLowerCase().includes(q))).length+" 个节点；最多展示 150 个。分区仅从节点名称推断，实际地区需独立核验。";
}
function renderSettings(){
 $("retry-recovery").classList.toggle("hidden",!overview.recovery_pending);
 const rows=[["管理软件版本","v"+(overview.version||"0.2.0")],
 ["主代理服务",overview.gateway?"运行中":"未连接"],["UDP 转发",overview.udp?"正常":"异常"],
 ["管理控制接口",overview.controller?"仅本机回环":"未启用"],
 ["安装模式",overview.mode||"—"],["订阅数量",overview.providers??"—"],
 ["配置恢复",overview.recovery_pending?"收据待处理，配置写入已锁定":"无待确认变更"],
 ["上次健康检查",dateText(overview.checked_at)]];
 $("device-info").innerHTML=rows.map(([l,r])=>'<div class="detail-row"><span>'+escapeHTML(l)+'</span><b>'+escapeHTML(r)+'</b></div>').join("");
}
$("login-form").addEventListener("submit",login);
$("logout").addEventListener("click",logout);
$("refresh").addEventListener("click",async()=>{if(await refreshAll())toast("已刷新实时状态")});
$("nav").addEventListener("click",e=>{const b=e.target.closest("[data-view]");if(b)openView(b.dataset.view)});
$("sub-search").addEventListener("input",renderSubscriptions);
$("node-search").addEventListener("input",renderNodes);
$("node-region-filter").addEventListener("change",renderNodes);
$("sub-form").addEventListener("submit",async e=>{
 e.preventDefault();const button=e.target.querySelector("button");button.disabled=true;
 const url=$("sub-url").value.trim();$("sub-url").value="";
 try{const result=await api("/api/subscription/add","POST",{name:$("sub-name").value.trim(),url});$("sub-form").reset();if(await refreshAll())toast("已保存，尚未启用。已检查 "+result.validated_nodes+" 个节点")}
 catch(err){toast(err.message,true)}
 finally{button.disabled=false}
});
$("sub-list").addEventListener("click",async e=>{
 const b=e.target.closest("button");if(!b)return;
 if(b.dataset.subUpdate){const form=[...document.querySelectorAll("[data-form-update]")].find(f=>f.dataset.formUpdate===b.dataset.subUpdate);if(form)form.classList.toggle("hidden")}
 if(b.dataset.subDelete){if(!confirm("确认删除订阅 "+b.dataset.subDelete+"？只有未被分流组使用的订阅可以删除。"))return;
  b.disabled=true;try{await api("/api/subscription/delete","POST",{name:b.dataset.subDelete});if(await refreshAll())toast("订阅已删除，网关仍保持安全配置")}
  catch(err){toast(err.message,true)}finally{b.disabled=false}}
});
$("sub-list").addEventListener("submit",async e=>{
 const f=e.target.closest("[data-form-update]");if(!f)return;e.preventDefault();
 if(!confirm("确认验证并替换这个已保存的订阅地址？"))return;
 const b=f.querySelector("button");b.disabled=true;
 try{const field=f.querySelector("input[name=url]");const url=field.value.trim();field.value="";const x=await api("/api/subscription/update","POST",{name:f.dataset.formUpdate,url});f.reset();if(await refreshAll())toast("已验证 "+x.validated_nodes+" 个节点，订阅已更新")}
 catch(err){toast(err.message,true)}finally{b.disabled=false}
});
$("region-list").addEventListener("click",e=>{
 const b=e.target.closest("[data-move]");if(!b)return;
 const [a,d]=b.dataset.move.split(":").map(Number),t=a+d;
 if(t<0||t>=regionOrder.length)return;
 [regionOrder[a],regionOrder[t]]=[regionOrder[t],regionOrder[a]];renderRegions();
});
$("retry-recovery").addEventListener("click",async e=>{
 if(!confirm("重新核验配置？未提交的变更可能需要回滚并重启代理。"))return;
 const button=e.currentTarget;button.disabled=true;
 try{const result=await api("/api/recovery/retry","POST");await refreshAll();toast(result.message)}
 catch(err){toast(err.message,true)}finally{button.disabled=false}
});
$("save-region").addEventListener("click",async ()=>{
 if(!confirm("确认修改地区优先级？保存会重新加载网关配置，可能产生短暂网络抖动。"))return;
 const b=$("save-region");b.disabled=true;
 try{const x=await api("/api/region-order","POST",{order:regionOrder});await refreshAll();toast(x.message||"地区优先级已更新")}
 catch(err){toast(err.message,true)}finally{b.disabled=false}
});
$("node-table").addEventListener("click",async e=>{
 const b=e.target.closest("[data-test-node]");if(!b)return;
 const name=b.dataset.testNode;b.disabled=true;b.textContent="检测中...";
 try{const x=await api("/api/test-node","POST",{name});b.textContent=x.online?x.delay+" ms":"未连通"}
 catch(err){b.textContent="检测失败";toast(err.message,true)}
 setTimeout(()=>{b.textContent="测试连接";b.disabled=false},5500);
});
$("password-form").addEventListener("submit",async e=>{
 e.preventDefault();try{
  await api("/api/password","POST",{old:$("password-old").value,new:$("password-new").value});
  e.target.reset();csrf="";showApp(false);toast("密码已修改，请使用新密码重新登录")
 }catch(err){toast(err.message,true)}
});
(async()=>{
 try{
  const auth=await api("/api/session");
  if(auth.authenticated){csrf=auth.csrf;showApp(true);await refreshAll();}
  else showApp(false);
 }catch(_){showApp(false);toast("无法连接 F1 管理服务",true)}
 setInterval(()=>{if(!$("app").classList.contains("hidden"))refreshSummary()},30000);
})();
