let currentUser="";let currentPermissions=[];
function showSettingsTab(name,button){document.querySelectorAll(".settingsPage").forEach(x=>x.classList.remove("active"));document.querySelectorAll(".settingsTab").forEach(x=>x.classList.remove("active"));const page=document.getElementById("settings-"+name);if(page)page.classList.add("active");if(button)button.classList.add("active")}
function showTab(name,button){document.querySelectorAll(".tabpage").forEach(x=>x.classList.remove("active"));document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));const page=document.getElementById("tab-"+name);if(page)page.classList.add("active");if(button)button.classList.add("active")}
let csrfToken = "";
function bindEnterActions(){
 const loginPass=document.getElementById("loginPass");
 if(loginPass&&!loginPass.dataset.enterBound){loginPass.dataset.enterBound="1";loginPass.addEventListener("keydown",e=>{if(e.key==="Enter"){e.preventDefault();login()}})}
 const setup=document.getElementById("setupOverlay");
 if(setup&&!setup.dataset.enterBound){setup.dataset.enterBound="1";setup.addEventListener("keydown",e=>{if(e.key==="Enter"&&e.target&&e.target.tagName!=="TEXTAREA"){e.preventDefault();runSetup()}})}
 const pwdNew=document.getElementById("pwdNew");
 if(pwdNew&&!pwdNew.dataset.enterBound){pwdNew.dataset.enterBound="1";pwdNew.addEventListener("keydown",e=>{if(e.key==="Enter"){e.preventDefault();changePassword()}})}
}
document.addEventListener("DOMContentLoaded",()=>{bindEnterActions();loadAppVersion()});

async function login(){loadAppVersion();const error=document.getElementById("loginError");error.textContent="";try{const response=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:document.getElementById("loginUser").value,password:document.getElementById("loginPass").value})});const raw=await response.text();if(!response.ok)throw new Error(raw);document.getElementById("loginOverlay").style.display="none";if(!await restoreSession())throw new Error("Session restore failed");if(hasPerm("admin")){await loadEndpointSettings();await loadAppSettings();await loadUsers();await loadUpdateStatus();await loadMaintenance();await loadBackups();await loadProvisionSites()}if(hasPerm("migrations")){await loadStacks();await loadHistory()}if(hasPerm("dashboard_read")){await loadReadiness();await loadCapacity();await loadCluster()}}catch(e){error.textContent="Přihlášení se nezdařilo."}}
async function restoreSession(){try{const r=await fetch("/api/session",{cache:"no-store"});if(!r.ok)return false;const data=await r.json();csrfToken=data.csrf;currentUser=data.user||"";currentPermissions=data.permissions||[];applyLanguage(data.language||"cs");applyPermissions();document.getElementById("loginOverlay").style.display="none";return true}catch(_){return false}}
let selectedStackId=null;let selectedDetail=null;
function esc(value){const div=document.createElement("div");div.textContent=value==null?"":String(value);return div.innerHTML}
async function getJson(url){const response=await fetch(url,{cache:"no-store"});if(!response.ok)throw new Error(await response.text());return response.json()}
async function loadAppVersion(){try{const d=await getJson("/health");const el=document.getElementById("appVersion");if(el)el.textContent="v"+d.version}catch(_){}}
function percent(part,total){if(!total)return 0;return Math.max(0,Math.min(100,part/total*100))}

async function loadReadiness(){
 const box=document.getElementById("nodeReadiness");if(!box)return;
 box.innerHTML='<div class="muted">Kontroluji připravenost endpointů...</div>';
 try{
  const data=await getJson("/api/nodes/readiness");box.innerHTML="";
  data.nodes.forEach(function(node){
   const item=document.createElement("div");item.className="item readinessNode";
   if(node.error){item.innerHTML="<strong>"+esc(node.name||("Endpoint "+node.id))+"</strong><div class='error'>"+esc(node.error)+"</div>";box.appendChild(item);return}
   const head=document.createElement("div");head.className="readinessHead";
   head.innerHTML="<div><strong>"+esc(node.name)+"</strong><div class='muted'>"+esc(node.host_ip||"IP nezjištěna")+(node.site?" · "+esc(node.site):"")+"</div></div><span class='badge "+(node.ready?"running":"stopped")+"'>"+(node.ready?"READY":"SETUP REQUIRED")+"</span>";
   item.appendChild(head);
   const checks=document.createElement("div");checks.className="readinessChecks";
   const labels={docker:"Docker",host_ip:"Host IP",capacity_agent:"Node Agent",data_disk:"DATA /srv",firewall:"Firewall",migration:"Migrace"};
   const required=new Set(node.required_checks||Object.keys(labels));Object.keys(labels).forEach(function(key){const ch=node.checks[key]||{};if(!required.has(key)){const spacer=document.createElement("div");spacer.className="readinessCheck readinessCheckSpacer";spacer.setAttribute("aria-hidden","true");checks.appendChild(spacer);return;}const row=document.createElement("div");row.className="readinessCheck "+(ch.ok?"checkOk":"checkError");row.innerHTML="<span class='checkIcon'>"+(ch.ok?"✓":"×")+"</span><span><strong>"+labels[key]+"</strong><small>"+esc(ch.message||"")+"</small></span>";checks.appendChild(row)});
   item.appendChild(checks);const role=document.createElement("div");role.className="muted";role.textContent="Role: "+(node.role||"NODE");item.insertBefore(role,checks);
   if(hasPerm("admin")&&(node.role||"").toUpperCase()==="NODE"){const actions=document.createElement("div");actions.className="actions";if(!node.ready){const btn=document.createElement("button");btn.textContent="Připravit NODE";btn.onclick=function(){prepareNode(node.id,btn)};actions.appendChild(btn)}const fw=document.createElement("button");fw.className="secondary";fw.textContent="Nastavit firewall";const view=document.createElement("button");view.className="secondary";view.textContent="Celý firewall";view.onclick=function(){showFirewall(node.id,node.name)};actions.appendChild(view);fw.onclick=function(){configureFirewall(node.id)};actions.appendChild(fw);item.appendChild(actions)}
   box.appendChild(item);
  });
 }catch(e){box.innerHTML='<div class="error item">'+esc(e.message)+'</div>'}
}
const prepareNodeSteps=[["endpoint","Endpoint / Host IP"],["migration","Povolení migrací"],["image","Capacity Agent image"],["container","Spuštění Capacity Agentu"],["health","Ověření portu 9100"],["disk","DATA /srv"],["firewall","Firewall"],["ready","NODE readiness"]];
function renderPrepareNodeProgress(box){
 box.innerHTML="<div style='margin-top:12px'><strong>Průběh přípravy NODE</strong></div>"+prepareNodeSteps.map((x,i)=>"<div id='prep-step-"+x[0]+"' style='padding:3px 0'><span class='prepIcon' style='display:inline-block;width:22px'>"+(i===0?"◌":"○")+"</span><span>"+esc(x[1])+"</span><small class='muted prepDetail' style='margin-left:8px'></small></div>").join("");
}
function updatePrepareNodeStep(id,status,detail){
 const row=document.getElementById("prep-step-"+id);if(!row)return;
 const icon=row.querySelector(".prepIcon"),d=row.querySelector(".prepDetail");
 icon.textContent=status==="done"?"✓":status==="error"?"✕":"◌";icon.style.color=status==="done"?"#86efac":status==="error"?"#f87171":"";
 if(d&&detail)d.textContent=detail;
 if(status==="done"){let n=row.nextElementSibling;if(n){const ni=n.querySelector(".prepIcon");if(ni&&ni.textContent==="○")ni.textContent="◌"}}
}
async function prepareNode(endpointId,button){
 const original=button.textContent;button.disabled=true;button.textContent="Připravuji NODE…";
 const item=button.closest(".item"),progress=document.createElement("div");progress.className="prepareNodeProgress";item.appendChild(progress);renderPrepareNodeProgress(progress);
 try{
  const r=await fetch("/api/endpoints/"+endpointId+"/prepare/stream",{method:"POST",headers:{"X-CSRF-Token":csrfToken}});
  if(!r.ok)throw new Error(await r.text());
  const reader=r.body.getReader(),decoder=new TextDecoder();let buf="",result=null;
  while(true){const z=await reader.read();if(z.done)break;buf+=decoder.decode(z.value,{stream:true});const lines=buf.split("\n");buf=lines.pop();for(const line of lines){if(!line.trim())continue;const e=JSON.parse(line);if(e.type==="progress")updatePrepareNodeStep(e.step,e.status||"done",e.detail||"");else if(e.type==="error"){throw new Error(e.detail||"Příprava NODE selhala");}else if(e.type==="result")result=e.result}}
  if(!result)throw new Error("Příprava NODE skončila bez výsledku.");
  updatePrepareNodeStep("ready","done","NODE je připraven");
  await new Promise(resolve=>setTimeout(resolve,600));
  await loadEndpointSettings();await loadReadiness();await loadCapacity();await loadCluster();
 }catch(e){updatePrepareNodeStep("ready","error",e.message);const err=document.createElement("div");err.className="error";err.style.marginTop="8px";err.textContent=e.message;progress.appendChild(err);button.disabled=false;button.textContent=original;try{await loadEndpointSettings();await loadReadiness();await loadCapacity();await loadCluster()}catch(_){}}
}

function dashboardDonut(d,label){
 if(!d)return "<div class='diskDonut unavailable'><div class='donutVisual'></div><div><strong>"+esc(label)+"</strong><small>nelze zjistit</small></div></div>";
 const pct=Math.max(0,Math.min(100,Number(d.percent)||0));
 return "<div class='diskDonut'><div class='donutVisual' style='--pct:"+pct+"'><span>"+pct.toFixed(0)+"%</span></div><div><strong>"+esc(label)+"</strong><small>"+esc(d.used_human)+" / "+esc(d.total_human)+"<br>volno "+esc(d.free_human)+"</small></div></div>";
}
function dashboardMetric(label,value,pct){
 const p=Math.max(0,Math.min(100,Number(pct)||0));
 return "<div class='nodeMetric'><div><span>"+esc(label)+"</span><strong>"+esc(value)+"</strong></div><div class='metricTrack'><span style='width:"+p+"%'></span></div></div>";
}
async function loadCluster(){
 const nodesBox=document.getElementById("clusterDashboard"),stacksBox=document.getElementById("dashboardStacks");
 if(nodesBox)nodesBox.innerHTML='<div class="muted">Načítám NODE servery...</div>';
 if(stacksBox)stacksBox.innerHTML='<div class="muted">Načítám stacky...</div>';
 try{
  const data=await getJson("/api/cluster");
  if(stacksBox){stacksBox.innerHTML="";const grid=document.createElement("div");grid.className="dashboardCardGrid stackCardGrid";
   (data.stacks||[]).forEach(stack=>{const card=document.createElement("div");card.className="dashboardMiniCard stackCard";const domains=(stack.domains||[]).length?(stack.domains||[]).map(d=>"<span class='domain'>"+esc(d)+"</span>").join(""):"<span class='muted'>bez domény</span>";card.innerHTML="<div class='cardTop'><div><span class='eyebrow'>STACK ID "+esc(stack.id)+"</span><h3>"+esc(stack.name)+"</h3></div><span class='badge "+(stack.status===1?"running":"stopped")+"'>"+(stack.status===1?"Running":"Stopped")+"</span></div><div class='stackMeta'><div><span>NODE</span><strong>"+esc(stack.endpoint)+"</strong></div><div><span>VELIKOST</span><strong>"+esc(stack.size_human||"—")+"</strong></div></div><div class='stackDomains'>"+domains+"</div>";card.onclick=async()=>{showTab("migrations",document.getElementById("tabButtonMigrations"));await showDetail(stack.id)};grid.appendChild(card)});
   if(!(data.stacks||[]).length)grid.innerHTML="<div class='muted'>Žádné stacky.</div>";stacksBox.appendChild(grid)}
  if(nodesBox){nodesBox.innerHTML="";const grid=document.createElement("div");grid.className="dashboardCardGrid nodeCardGrid";
   (data.nodes||[]).forEach(node=>{const card=document.createElement("div");card.className="dashboardMiniCard nodeCard";if(node.error){card.innerHTML="<h3>"+esc(node.name||("Endpoint "+node.id))+"</h3><div class='error'>"+esc(node.error)+"</div>";grid.appendChild(card);return}
    const cpu=Math.max(0,Math.min(100,Number(node.cpu_percent_containers)||0)),ramUsed=node.ram_total-node.ram_available_estimate,ramPct=percent(ramUsed,node.ram_total);
    card.innerHTML="<div class='cardTop'><div><span class='eyebrow'>NODE</span><h3>"+esc(node.name)+"</h3></div><span class='muted'>"+esc(node.running_containers)+" kontejnerů</span></div><div class='nodeMetrics'>"+dashboardMetric("CPU",cpu.toFixed(1)+" %",cpu)+dashboardMetric("RAM",esc(node.ram_used_human)+" / "+esc(node.ram_total_human),ramPct)+"</div><div class='diskDonuts'>"+dashboardDonut(node.data_disk,"DATA /srv")+dashboardDonut(node.system_disk,"SYSTEM / Docker")+"</div><div class='nodeFooter'><span>Docker data</span><strong>"+esc(node.docker_used_human)+"</strong></div>";grid.appendChild(card)});
   nodesBox.appendChild(grid)}
 }catch(error){if(nodesBox)nodesBox.innerHTML='<div class="error item">'+esc(error.message)+'</div>';if(stacksBox)stacksBox.innerHTML='<div class="error item">'+esc(error.message)+'</div>'}
}
async function loadCapacity(){const box=document.getElementById("capacity");if(!box)return;box.innerHTML='<div class="muted">Načítám kapacitu endpointů...</div>';try{const data=await getJson("/api/nodes/capacity");box.innerHTML="";data.nodes.forEach(function(node){const item=document.createElement("div");item.className="item";if(node.error){item.innerHTML="<strong>"+esc(node.name||("Endpoint "+node.id))+"</strong><div class='error'>"+esc(node.error)+"</div>";box.appendChild(item);return}const recommended=node.id===data.recommended_endpoint_id?" · DOPORUČENÝ CÍL":"";function diskRow(title,d,path,error){if(!d)return "<div class='capacityDisk'><div class='capacityDiskHead'><span>"+title+" <span class='muted'>"+esc(path)+"</span></span><strong>nelze zjistit</strong></div>"+(error?"<div class='muted'>"+esc(error)+"</div>":"")+"</div>";const cls=d.percent>=90?"danger":d.percent>=75?"warning":"ok";return "<div class='capacityDisk'><div class='capacityDiskHead'><span>"+title+" <span class='muted'>"+esc(path)+"</span></span><strong>"+Number(d.percent).toFixed(1)+" %</strong></div><div class='capacityBar'><div class='capacityBarFill "+cls+"' style='width:"+Math.min(100,d.percent)+"%'></div></div><div class='muted'>Obsazeno "+esc(d.used_human)+" / "+esc(d.total_human)+" · volno "+esc(d.free_human)+"</div></div>"}item.innerHTML="<strong>"+esc(node.name)+recommended+"</strong><div class='muted'>CPU: "+node.cpu_count+" · RAM: "+esc(node.ram_used_human)+" / "+esc(node.ram_total_human)+" · odhad volné: "+esc(node.ram_available_human)+" · CPU load kontejnerů: "+node.cpu_percent_containers.toFixed(1)+"% · kontejnery: "+node.running_containers+"</div>"+diskRow("DATA",node.data_disk,node.data_path,node.data_disk_error)+diskRow("SYSTEM / Docker",node.system_disk,node.docker_root,node.system_disk_error)+"<div class='muted'>Docker images + volumes: "+esc(node.docker_used_human)+"</div>";if((!node.data_disk||!node.system_disk)&&hasPerm("admin")){const actions=document.createElement("div");actions.className="actions";const install=document.createElement("button");install.textContent="Nainstalovat / opravit Capacity Agent";install.onclick=function(){installCapacityAgent(node.id,install)};actions.appendChild(install);item.appendChild(actions)}box.appendChild(item)});const note=document.createElement("div");note.className="muted";note.style.marginTop="10px";note.textContent="Migration Advisor používá jako úložnou kapacitu DATA filesystem /srv. SYSTEM/Docker disk je zobrazen samostatně.";box.appendChild(note)}catch(error){box.innerHTML='<div class="error item">'+esc(error.message)+"</div>"}}
async function loadAdvisor(stackId){const box=document.getElementById("advisorBox");if(!box)return;box.innerHTML='<div class="muted item">Vyhodnocuji cílové endpointy...</div>';try{const data=await getJson("/api/stacks/"+encodeURIComponent(stackId)+"/advisor");box.innerHTML="";data.candidates.forEach(function(node){const item=document.createElement("div");item.className="item";if(node.error){item.innerHTML="<strong>"+esc(node.name||("Endpoint "+node.id))+"</strong><div class='error'>"+esc(node.error)+"</div>";box.appendChild(item);return}const recommended=node.id===data.recommended_endpoint_id?" · DOPORUČENO":"";let html="<strong>"+esc(node.name)+recommended+"</strong><div class='muted'>RAM volná odhad: "+esc(node.ram_available_human)+" · CPU: "+node.cpu_percent_containers.toFixed(1)+"% · kontejnery: "+node.running_containers+"</div>";if(node.warnings&&node.warnings.length)html+="<div class='muted'>"+node.warnings.map(esc).join(" · ")+"</div>";item.innerHTML=html;box.appendChild(item)});const targetSelect=document.querySelector("select[id*='target'], select[name*='target']");if(targetSelect&&data.recommended_endpoint_id){const recommendedId=String(data.recommended_endpoint_id);Array.from(targetSelect.options).forEach(function(option){const base=option.textContent.replace(/ · doporučeno$/i,"");option.textContent=String(option.value)===recommendedId?base+" · doporučeno":base});targetSelect.value=recommendedId}}catch(error){box.innerHTML='<div class="error item">'+esc(error.message)+'</div>'}}
async function loadHistory(){const box=document.getElementById("history");try{const jobs=await getJson("/api/migrations");box.innerHTML="";if(!jobs.length){box.innerHTML='<div class="muted">Zatím žádná uložená migrace.</div>';return}jobs.forEach(function(job){const item=document.createElement("div");item.className="item";const title=document.createElement("strong");let name="Stack ID "+job.stack_id;if(job.result&&job.result.stack)name=job.result.stack;title.textContent=name+" · "+job.status;const meta=document.createElement("div");meta.className="muted";let route="";if(job.result){route=(job.result.source||"?")+" → "+(job.result.target||"?");if(job.result.finalized)route+=" · "+job.result.finalized}else route="target endpoint ID "+job.target_id;meta.textContent=route+" · "+(job.created_at||"");item.appendChild(title);item.appendChild(meta);if(job.status==="success"&&job.result&&!job.result.finalized){const actions=document.createElement("div");actions.style.marginTop="10px";const confirm=document.createElement("button");confirm.textContent="Potvrdit migraci";confirm.onclick=function(){finalizeMigration(job.id,"confirm")};const rollback=document.createElement("button");rollback.textContent="Vrátit zpět";rollback.style.marginLeft="10px";rollback.style.background="#b45309";rollback.onclick=function(){finalizeMigration(job.id,"rollback")};actions.appendChild(confirm);actions.appendChild(rollback);item.appendChild(actions)}box.appendChild(item)})}catch(error){box.innerHTML='<div class="error item">'+esc(error.message)+'</div>'}}

let endpointDrafts=[];let endpointSettingsDirty=false;
function toggleEndpointSettings(){const body=document.getElementById("endpointSettingsBody");const button=document.getElementById("endpointToggle");const open=body.style.display==="none";body.style.display=open?"block":"none";button.textContent=open?"Sbalit":"Rozbalit"}
function markEndpointSettingsDirty(){endpointSettingsDirty=true;const button=document.getElementById("saveEndpointSettings");if(button)button.disabled=false;const state=document.getElementById("endpointSaveState");if(state)state.textContent="Neuložené změny"}
async function loadEndpointSettings(){const box=document.getElementById("endpointSettings");if(!box)return;box.innerHTML='<div class="muted">Načítám endpointy...</div>';try{endpointDrafts=await getJson("/api/endpoints/settings");endpointSettingsDirty=false;const save=document.getElementById("saveEndpointSettings");if(save)save.disabled=true;const state=document.getElementById("endpointSaveState");if(state)state.textContent="";const enabled=endpointDrafts.filter(ep=>ep.migration_enabled).length;const summary=document.getElementById("endpointSummary");if(summary)summary.textContent="· "+enabled+" z "+endpointDrafts.length+" povoleno";box.innerHTML="";endpointDrafts.forEach(function(ep,index){const row=document.createElement("div");row.className="item";row.style.display="grid";row.style.gridTemplateColumns="";row.style.gap="10px";row.style.alignItems="center";const info=document.createElement("div");info.innerHTML="<strong>"+esc(ep.name)+"</strong><div class='muted'>"+esc(ep.url||("Endpoint ID "+ep.id))+"</div>";const ip=document.createElement("input");ip.placeholder="Host IP (volitelné)";ip.value=ep.host_ip||"";const lanIp=document.createElement("input");lanIp.placeholder="LAN IP pro aplikace/proxy";lanIp.value=ep.lan_ip||"";const role=document.createElement("select");["NONE","NODE","PROXY","MGMT","PORTAINER"].forEach(v=>{const o=document.createElement("option");o.value=v;o.textContent=v==="NONE"?"Bez role":v;o.selected=(ep.role||"NONE")===v;role.appendChild(o)});role.onchange=function(){endpointDrafts[index].role=role.value;endpointDrafts[index].migration_enabled=role.value==="NODE"&&cb.checked;markEndpointSettingsDirty()};const publicIp=document.createElement("input");publicIp.placeholder="Public IP (DNS)";publicIp.value=ep.public_ip||"";const site=document.createElement("input");site.placeholder="Site / lokalita (např. DC2)";site.value=ep.site||"";const agentUrl=document.createElement("input");agentUrl.placeholder="Node Agent URL (REMOTE např. http://78.24.11.48:9111)";agentUrl.value=ep.agent_url||"";const toggle=document.createElement("label");toggle.style.whiteSpace="nowrap";const cb=document.createElement("input");cb.type="checkbox";cb.checked=!!ep.migration_enabled;toggle.appendChild(cb);toggle.appendChild(document.createTextNode(" Povolit migrace"));cb.onchange=function(){endpointDrafts[index].migration_enabled=cb.checked;markEndpointSettingsDirty()};ip.oninput=function(){endpointDrafts[index].host_ip=ip.value;markEndpointSettingsDirty()};lanIp.oninput=function(){endpointDrafts[index].lan_ip=lanIp.value;markEndpointSettingsDirty()};publicIp.oninput=function(){endpointDrafts[index].public_ip=publicIp.value;markEndpointSettingsDirty()};site.oninput=function(){endpointDrafts[index].site=site.value;markEndpointSettingsDirty()};agentUrl.oninput=function(){endpointDrafts[index].agent_url=agentUrl.value;markEndpointSettingsDirty()};row.appendChild(info);row.appendChild(role);row.appendChild(ip);row.appendChild(lanIp);row.appendChild(publicIp);row.appendChild(site);row.appendChild(agentUrl);row.appendChild(toggle);
if(["NODE","PROXY"].includes((ep.role||"").toUpperCase())){
 const remove=document.createElement("button");remove.className="secondary";remove.textContent="Odebrat server";
 remove.onclick=function(){removeEndpoint(ep,remove)};row.appendChild(remove)
}
box.appendChild(row)});if(!endpointDrafts.length)box.innerHTML='<div class="muted">Portainer nevrátil žádné endpointy.</div>'}catch(error){box.innerHTML='<div class="error item">'+esc(error.message)+'</div>'}}
async function saveEndpointSettings(){if(!endpointSettingsDirty)return;const button=document.getElementById("saveEndpointSettings");const state=document.getElementById("endpointSaveState");button.disabled=true;state.textContent="Ukládám…";try{for(const ep of endpointDrafts){const r=await fetch("/api/endpoints/"+ep.id+"/settings",{method:"PUT",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify({migration_enabled:!!ep.migration_enabled,host_ip:ep.host_ip||"",lan_ip:ep.lan_ip||"",site:ep.site||"",public_ip:ep.public_ip||"",agent_url:ep.agent_url||"",role:ep.role||"NONE"})});if(!r.ok)throw new Error(await r.text())}endpointSettingsDirty=false;state.textContent="✓ Nastavení uloženo";await loadEndpointSettings();state.textContent="✓ Nastavení uloženo";await loadCapacity();await loadCluster()}catch(e){button.disabled=false;state.textContent="Uložení selhalo";alert("Uložení endpointů selhalo: "+e.message)}}

function hasPerm(p){return currentPermissions.includes(p)}
function applyPermissions(){const rules={tabButtonDashboard:"dashboard_read",tabButtonMigrations:"migrations",tabButtonDns:"dns_read",tabButtonSettings:"admin"};Object.entries(rules).forEach(([id,p])=>{const e=document.getElementById(id);if(e)e.style.display=hasPerm(p)?"":"none"});const nb=document.getElementById("newDnsButton");if(nb)nb.style.display=hasPerm("dns_write")?"":"none";document.querySelectorAll("[data-permission]").forEach(e=>{e.style.display=hasPerm(e.dataset.permission)?"":"none"});const active=document.querySelector(".tab.active");if(active&&active.style.display==="none"){const first=Array.from(document.querySelectorAll(".tab")).find(x=>x.style.display!=="none");if(first)first.click()}}
async function bootstrap(){try{const s=await getJson("/api/setup/status");if(s.required){document.getElementById("loginOverlay").style.display="none";document.getElementById("setupOverlay").style.display="flex";return}}catch(e){}const ok=await restoreSession();if(ok){if(hasPerm("admin")){loadEndpointSettings();loadAppSettings();loadUsers();loadMaintenance();loadBackups()}if(hasPerm("migrations")){loadStacks();loadHistory()}if(hasPerm("dashboard_read")){loadReadiness();loadCapacity();loadCluster()}}}
async function runSetup(){const err=document.getElementById("setupError");err.textContent="";const payload={username:document.getElementById("setupUser").value,password:document.getElementById("setupPass").value,language:document.getElementById("setupLanguage").value};const r=await fetch("/api/setup",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});if(!r.ok){err.textContent=await r.text();return}err.textContent="✓ Nastavení uloženo. Můžeš se přihlásit.";setTimeout(()=>location.reload(),700)}
async function loadAppSettings(){try{const s=await getJson("/api/app-settings");document.getElementById("cfgPortainerUrl").value=s.portainer_url||"";document.getElementById("cfgVasUrl").value=s.vas_hosting_api_url||"https://portal.vas-hosting.cz/api/v1";document.getElementById("cfgLanguage").value=s.language||"cs";applyLanguage(s.language||"cs");document.getElementById("cfgState").textContent="Portainer token: "+(s.portainer_token_set?"nastaven":"nenastaven")+" · Váš Hosting API: "+(s.vas_hosting_api_key_set?"nastaveno":"nenastaveno");renderInitialInfrastructureState(s)}catch(e){}}
function renderInitialInfrastructureState(s){
 const ready=document.getElementById("initialInfraReady"),setup=document.getElementById("initialInfraSetup"),badge=document.getElementById("initialInfraBadge");if(!ready||!setup)return;
 const configured=!!(s.portainer_url&&s.portainer_token_set);
 if(configured){setup.style.display="none";ready.style.display="flex";if(badge){badge.textContent="OK";badge.className="badge running"}ready.innerHTML="<div><strong>✓ Portainer je nastavený</strong><div class='muted'>"+esc(s.portainer_url)+" · API token uložen · první infrastrukturu už není potřeba znovu připravovat.</div></div><button class='secondary' type='button' onclick='showInitialInfrastructureSetup()'>Změnit / znovu připravit</button>"}
 else{ready.style.display="none";setup.style.display="block";if(badge){badge.textContent="SETUP";badge.className="badge stopped"}}
}
function showInitialInfrastructureSetup(){const ready=document.getElementById("initialInfraReady"),setup=document.getElementById("initialInfraSetup");if(ready)ready.style.display="none";if(setup)setup.style.display="block"}
async function saveAppSettings(){const p={portainer_url:document.getElementById("cfgPortainerUrl").value,portainer_token:document.getElementById("cfgPortainerToken").value,vas_hosting_api_url:document.getElementById("cfgVasUrl").value,vas_hosting_api_key:document.getElementById("cfgVasKey").value,language:document.getElementById("cfgLanguage").value};const r=await fetch("/api/app-settings",{method:"PUT",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify(p)});if(!r.ok){alert(await r.text());return}document.getElementById("cfgState").textContent="✓ Uloženo a aktivní.";document.getElementById("cfgPortainerToken").value="";document.getElementById("cfgVasKey").value="";applyLanguage(p.language)}
async function changePassword(){const p={current_password:document.getElementById("pwdCurrent").value,new_password:document.getElementById("pwdNew").value};const r=await fetch("/api/account/password",{method:"PUT",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify(p)});if(!r.ok){alert(await r.text());return}document.getElementById("pwdCurrent").value="";document.getElementById("pwdNew").value="";alert("Heslo bylo změněno.")}
async function installCapacityAgent(endpointId,button){
 const original=button.textContent;button.disabled=true;button.textContent="Instaluji Capacity Agent…";
 try{
  const r=await fetch("/api/endpoints/"+endpointId+"/capacity-agent/install",{method:"POST",headers:{"X-CSRF-Token":csrfToken}});
  const raw=await r.text();if(!r.ok)throw new Error(raw);
  await loadEndpointSettings();await loadCapacity();await loadCluster();
 }catch(e){alert("Instalace Capacity Agent selhala: "+e.message);button.disabled=false;button.textContent=original}
}

async function loadUpdateStatus(){
 const box=document.getElementById("updateState"),btn=document.getElementById("updateButton");if(!box)return;
 box.textContent="Kontroluji dostupnou verzi…";if(btn)btn.disabled=true;
 try{const d=await getJson("/api/update/status");
  let msg="Běžící verze: "+esc(d.version||"neznámá")+" · kanál: GHCR latest";
  if(d.latest_version){msg+=" · dostupná verze: "+esc(d.latest_version);msg+=d.update_available?" · NOVÁ VERZE JE K DISPOZICI":" · ✓ používáš aktuální verzi"}
  else if(d.check_error)msg+=" · kontrola latest selhala: "+esc(d.check_error);
  if(!d.helper_available)msg+=" · host update helper není nainstalován";
  if(d.result)msg+=" · poslední stav: "+esc(d.result);
  box.innerHTML=msg;
  if(btn)btn.disabled=!d.helper_available;
 }catch(e){box.textContent="Stav aktualizace nelze načíst: "+e.message;if(btn)btn.disabled=true}
}
async function runSelfUpdate(){
 const btn=document.getElementById("updateButton"),box=document.getElementById("updateState");
 if(!confirm("Stáhnout aktuální GHCR :latest a restartovat DockerStackMover?\n\nNastavení a data zůstanou zachována."))return;
 btn.disabled=true;box.textContent="Předávám aktualizaci MGMT hostu…";
 try{const r=await fetch("/api/update",{method:"POST",headers:{"X-CSRF-Token":csrfToken}});const raw=await r.text();if(!r.ok)throw new Error(raw);
  box.textContent="Aktualizace běží · DSM se může na chvíli odpojit. Čekám na nový kontejner…";
  const deadline=Date.now()+120000;
  while(Date.now()<deadline){await new Promise(x=>setTimeout(x,2500));try{const s=await fetch("/api/setup/status",{cache:"no-store"});if(s.ok){const d=await fetch("/api/update/status",{cache:"no-store"});if(d.ok){const j=await d.json();if(String(j.result||"").startsWith("OK")){await loadUpdateStatus();return}if(String(j.result||"").startsWith("ERROR")){box.textContent="Aktualizace selhala: "+j.result;btn.disabled=false;return}}}}catch(_){}}
  box.textContent="Aktualizace byla spuštěna, ale web se do 120 s nepotvrdil. Obnov stránku a zkontroluj stav.";
 }catch(e){box.textContent="Aktualizace selhala: "+e.message;btn.disabled=false}
}

async function loadMaintenance(){
 const box=document.getElementById("maintenance");if(!box)return;box.innerHTML='<div class="muted">Načítám…</div>';
 try{const d=await getJson("/api/maintenance");box.innerHTML="";
  d.nodes.forEach(n=>{const x=document.createElement("div");x.className="item";const a=n.capacity_agent||{};
   x.innerHTML="<strong>"+esc(n.name)+"</strong><div class='muted'>Docker: "+(n.docker?"online":"offline")+" · Capacity Agent: "+(a.installed?esc(a.state||"installed"):"není nainstalován")+(a.image?" · "+esc(a.image):"")+"</div>";
   if(n.docker){const btn=document.createElement("button");btn.className="secondary";btn.style.marginTop="10px";btn.textContent="Aktualizovat Capacity Agent";btn.onclick=async()=>{btn.disabled=true;try{const r=await fetch("/api/endpoints/"+n.id+"/capacity-agent/upgrade",{method:"POST",headers:{"X-CSRF-Token":csrfToken}});if(!r.ok)throw new Error(await r.text());await loadMaintenance();await loadReadiness()}catch(e){alert(e.message);btn.disabled=false}};x.appendChild(btn)}box.appendChild(x)})}
 catch(e){box.innerHTML='<div class="error item">'+esc(e.message)+'</div>'}
}
async function loadBackups(){
 const box=document.getElementById("backups");if(!box)return;try{const d=await getJson("/api/backups");box.innerHTML=d.backups.length?"":"<div class='muted'>Zatím žádné snapshoty.</div>";
 d.backups.forEach(b=>{const x=document.createElement("div");x.className="item";const v=b.value||{};x.innerHTML="<strong>"+esc((v.stack||{}).name||v.id)+"</strong><div class='muted'>"+esc(v.type||"backup")+" · "+esc(v.created_at||b.updated_at)+" · "+((v.volumes||[]).length)+" volumes</div>";box.appendChild(x)})}catch(e){box.innerHTML='<div class="error item">'+esc(e.message)+'</div>'}
}
async function backupSelectedStack(){
 if(!selectedStackId)return;if(!confirm("Vytvořit konzistentní snapshot persistentních volumes? Stack bude krátce zastaven."))return;
 try{const r=await fetch("/api/stacks/"+selectedStackId+"/backup",{method:"POST",headers:{"X-CSRF-Token":csrfToken}});if(!r.ok)throw new Error(await r.text());alert("Snapshot vytvořen.");await loadBackups()}catch(e){alert("Snapshot selhal: "+e.message)}
}

async function configureFirewall(endpointId){
 const sourceText=prompt("Povolené management IPv4 adresy (odděl čárkou):","78.24.11.49");if(!sourceText)return;
 const portText=prompt("Chráněné management TCP porty (odděl čárkou):","9001,9100");if(!portText)return;
 const sources=sourceText.split(",").map(x=>x.trim()).filter(Boolean),ports=portText.split(",").map(x=>Number(x.trim())).filter(x=>Number.isInteger(x)&&x>0&&x<65536);
 if(!sources.length||!ports.length){alert("Je nutná alespoň jedna IP a jeden platný port.");return}
 if(!confirm("Aplikuji firewall DOČASNĚ na 90 sekund. Pokud jej nepotvrdíš, automaticky se vrátí předchozí stav.\n\nIP: "+sources.join(", ")+"\nPorty: "+ports.join(", ")))return;
 try{
  const r=await fetch("/api/endpoints/"+endpointId+"/firewall",{method:"PUT",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify({management_sources:sources,management_ports:ports,confirm_timeout:90})});
  const raw=await r.text();if(!r.ok)throw new Error(raw);const d=JSON.parse(raw);
  if(!d.transaction_id)throw new Error("Agent nevrátil firewall transaction ID.");
  const ok=confirm("Nová pravidla jsou aktivní a agent po změně odpovídá.\n\nPotvrdit je natrvalo?\n\nZrušit = okamžitý rollback. Bez potvrzení proběhne rollback automaticky.");
  const action=ok?"confirm":"rollback";
  const rr=await fetch("/api/endpoints/"+endpointId+"/firewall/"+action+"/"+encodeURIComponent(d.transaction_id),{method:"POST",headers:{"X-CSRF-Token":csrfToken}});
  if(!rr.ok)throw new Error(await rr.text());
  await loadReadiness();alert(ok?"Firewall potvrzen.":"Firewall vrácen do předchozího stavu.");
 }catch(e){alert("Firewall změna nebyla potvrzena: "+e.message+"\nPokud byla pravidla aplikována, agent je automaticky vrátí po vypršení ochranného času.")}
}

async function showFirewall(endpointId,name){
 try{
  const d=await getJson("/api/endpoints/"+endpointId+"/firewall"),rs=(d.full_ruleset||{}).nftables||[];
  const published=[],internal=[],policies=[];
  rs.forEach(x=>{
   if(x.chain&&x.chain.hook)policies.push({family:x.chain.family,table:x.chain.table,chain:x.chain.name,policy:x.chain.policy||"—"});
   if(!x.rule)return;const r=x.rule,e=r.expr||[];let port=null,addr="",action="",iif="",oif="";
   e.forEach(z=>{if(z.match&&z.match.left&&z.match.left.payload&&z.match.left.payload.field==="dport")port=z.match.right;if(z.match&&z.match.left&&z.match.left.payload&&z.match.left.payload.field==="daddr")addr=z.match.right;if(z.match&&z.match.left&&z.match.left.meta&&z.match.left.meta.key==="iifname")iif=z.match.right;if(z.match&&z.match.left&&z.match.left.meta&&z.match.left.meta.key==="oifname")oif=z.match.right;if(z.accept!==undefined)action="ACCEPT";if(z.drop!==undefined)action="DROP";if(z.xt&&z.xt.type==="target")action=z.xt.name||"NAT"});
   if(!port)return;const item={family:r.family,table:r.table,chain:r.chain,port,address:addr,action:action||"RULE",iif,oif};
   if(r.table==="nat"&&r.chain==="DOCKER")published.push(item);else internal.push(item);
  });
  const raw=JSON.stringify(d.full_ruleset||d.ruleset||d,null,2),w=window.open("","_blank");
  const tr=p=>"<tr><td>"+esc(p.family)+"</td><td>TCP "+esc(p.port)+"</td><td>"+esc(p.address||"host")+"</td><td>"+esc(p.action)+"</td></tr>";
  const pub=published.map(tr).join(""),inside=internal.map(p=>"<tr><td>"+esc(p.family)+"</td><td>"+esc(p.table)+" / "+esc(p.chain)+"</td><td>TCP "+esc(p.port)+"</td><td>"+esc(p.address||"—")+"</td><td>"+esc(p.action)+"</td></tr>").join("");
  const pol=policies.map(p=>"<tr><td>"+esc(p.family)+"</td><td>"+esc(p.table)+" / "+esc(p.chain)+"</td><td>"+esc(p.policy)+"</td></tr>").join("");
  const managed=d.managed?"SPRAVOVÁN":"NENÍ SPRAVOVÁN";
  w.document.write("<title>Firewall - "+esc(name||endpointId)+"</title><style>body{font:14px system-ui;background:#0f172a;color:#e2e8f0;padding:28px;max-width:1200px;margin:auto}h2,h3{margin-top:20px}.card{background:#172033;border:1px solid #334155;border-radius:12px;padding:18px;margin:14px 0}.ok{color:#86efac}.warn{color:#fbbf24}.toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid #334155}button{padding:10px 14px;border:0;border-radius:8px;cursor:pointer;font-weight:650}summary{cursor:pointer;font-weight:650;padding:8px 0}pre{white-space:pre-wrap;overflow:auto}</style><div class='toolbar'><h2>Firewall · "+esc(name||("Endpoint "+endpointId))+"</h2><button id='editFw'>Upravit firewall</button></div><div class='card'><b>DockerStackMover firewall:</b> <span class='"+(d.managed?"ok":"warn")+"'>"+managed+"</span></div><div class='card'><h3>Publikované služby / host porty</h3><table><tr><th>Family</th><th>Host port</th><th>Cílová adresa</th><th>Akce</th></tr>"+(pub||"<tr><td colspan=4>Žádné publikované porty</td></tr>")+"</table></div><div class='card'><details><summary>Docker interní pravidla ("+internal.length+")</summary><table><tr><th>Family</th><th>Table / Chain</th><th>Port</th><th>Adresa</th><th>Akce</th></tr>"+(inside||"<tr><td colspan=5>Žádná</td></tr>")+"</table></details></div><div class='card'><h3>Host policy</h3><table><tr><th>Family</th><th>Table / Chain</th><th>Policy</th></tr>"+pol+"</table></div><details><summary>RAW nftables JSON</summary><pre>"+esc(raw)+"</pre></details>");
  w.document.getElementById("editFw").onclick=()=>{w.opener.configureFirewall(endpointId)};
 }catch(e){alert("Firewall nelze načíst: "+e.message)}
}


const provisioningSteps=[
 ["ssh","SSH připojení"],["preflight","Pre-flight kontrola"],["lan","LAN konfigurace"],["hostname","Hostname"],
 ["wg_key","WireGuard klíče"],["wg_peer","Registrace peeru na MAIN"],["wg_start","Spuštění WireGuardu"],
 ["wg_handshake","WireGuard handshake"],["wg_forward","WireGuard forwarding"],["data_disk","DATA disk /srv"],
 ["docker","Docker + Portainer Agent"],["firewall","Management firewall"],["main_test","MAIN → Portainer Agent"],
 ["portainer","Registrace v Portaineru"]
];
function renderProvisionProgress(state,role){
 const steps=provisioningSteps.filter(x=>!(role!=="NODE"&&x[0]==="data_disk"));
 state.innerHTML="<div style='margin-bottom:8px'><strong>Průběh provisioningu</strong></div>"+steps.map((x,i)=>"<div id='prov-step-"+x[0]+"' style='padding:3px 0'><span class='provIcon' style='display:inline-block;width:22px'>"+(i===0?"◌":"○")+"</span><span>"+esc(x[1])+"</span><small class='muted provDetail' style='margin-left:8px'></small></div>").join("");
}
function updateProvisionStep(id,status,detail){
 const row=document.getElementById("prov-step-"+id);if(!row)return;
 const icon=row.querySelector(".provIcon"),d=row.querySelector(".provDetail");
 icon.textContent=status==="done"?"✓":status==="error"?"✕":"◌";
 icon.style.color=status==="done"?"#86efac":status==="error"?"#f87171":"";
 if(d&&detail)d.textContent=detail;
 if(status==="done"){let n=row.nextElementSibling;while(n&&!n.id.startsWith("prov-step-"))n=n.nextElementSibling;if(n){const ni=n.querySelector(".provIcon");if(ni&&ni.textContent==="○")ni.textContent="◌"}}
}
async function provisionServer(){
 const b=document.getElementById("provButton"),state=document.getElementById("provState");
 const payload={name:document.getElementById("provName").value,site:document.getElementById("provSite").value,public_ip:document.getElementById("provPublicIp").value,role:document.getElementById("provRole").value,
  host:document.getElementById("provHost").value,lan_ip:document.getElementById("provLanIp").value,management_ip:document.getElementById("provMgmtIp").value,data_disk:document.getElementById("provDataDisk").value||"AUTO",
  ssh_user:document.getElementById("provUser").value,ssh_password:document.getElementById("provPassword").value,
  hub_host:document.getElementById("provHubHost").value,hub_ssh_user:document.getElementById("provHubUser").value,hub_ssh_password:document.getElementById("provHubPassword").value,
  hub_endpoint:document.getElementById("provHubEndpoint").value,hub_management_ip:"10.200.0.1",manager_management_ip:"10.200.0.1"};
 if(!payload.host||!payload.lan_ip||!payload.management_ip||!payload.ssh_password||!payload.hub_ssh_password){alert("Vyplň SSH adresu, LAN/management IP a obě SSH hesla.");return}
 if(!confirm("Připravit "+(payload.name||payload.host)+"?\n\nPo ověření WireGuardu budou porty 9001/9100 dostupné pouze přes management overlay."))return;
 b.disabled=true;renderProvisionProgress(state,payload.role);
 try{
  const r=await fetch("/api/provisioning/server/stream",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify(payload)});
  if(!r.ok)throw new Error(await r.text());
  const reader=r.body.getReader(),decoder=new TextDecoder();let buf="",result=null;
  while(true){const z=await reader.read();if(z.done)break;buf+=decoder.decode(z.value,{stream:true});const lines=buf.split("\n");buf=lines.pop();for(const line of lines){if(!line.trim())continue;const e=JSON.parse(line);if(e.type==="progress")updateProvisionStep(e.step,e.status||"done",e.detail||"");else if(e.type==="error"){if(e.step)updateProvisionStep(e.step,"error",e.detail);throw new Error(e.detail)}else if(e.type==="result")result=e.result}}
  if(!result)throw new Error("Provisioning skončil bez výsledku.");
  const title=document.createElement("div");title.style.cssText="color:#86efac;font-weight:700;margin-top:12px";title.textContent="✓ "+result.name+" připraven · Management: "+result.management_ip;state.appendChild(title);
  document.getElementById("provPassword").value="";document.getElementById("provHubPassword").value="";
  await loadEndpointSettings();await loadReadiness();
 }catch(e){const x=document.createElement("div");x.className="error";x.style.marginTop="12px";x.textContent=e.message;state.appendChild(x)}
 finally{b.disabled=false}
}


async function bootstrapFirstPortainer(){
 const b=document.getElementById("bootButton"),state=document.getElementById("bootState");
 const p={site:document.getElementById("bootSite").value.trim(),host:document.getElementById("bootHost").value.trim(),ssh_user:document.getElementById("bootUser").value.trim(),ssh_password:document.getElementById("bootPassword").value};
 if(!p.site||!p.host||!p.ssh_user||!p.ssh_password){state.className="error";state.textContent="Vyplň název lokality, SSH adresu, uživatele a heslo.";return}
 if(!confirm("Připravit první infrastrukturu "+p.site.toUpperCase()+" na serveru "+p.host+"?\n\nDockerStackMover automaticky připraví CONTROL/MGMT na .9, Docker, WireGuard HUB 10.200.0.1 a Portainer Server."))return;

 const steps=[
  ["ssh","SSH připojení"],
  ["ubuntu","Kontrola Ubuntu"],
  ["network","Síťová konfigurace"],
  ["hostname","Hostname"],
  ["docker","Docker"],
  ["wireguard","WireGuard HUB 10.200.0.1"],
  ["portainer","Portainer Server"],
  ["lan","LAN IP .9"],
  ["api","Inicializace Portainer API"],
  ["save","Uložení infrastruktury"]
 ];
 state.className="";state.innerHTML='<div style="font-weight:700;margin-bottom:8px">Příprava '+esc(p.site.toUpperCase())+'-MGMT</div>'+
  steps.map(([id,label])=>'<div id="bootStep-'+id+'" style="padding:4px 0"><span class="bootMark">○</span> '+esc(label)+'<span class="muted bootDetail"></span></div>').join('')+
  '<div id="bootProgress" class="muted" style="margin-top:10px">0 / '+steps.length+' hotovo</div>';
 let done=new Set();
 function update(step,status,detail){
   const row=document.getElementById("bootStep-"+step);if(!row)return;
   const mark=row.querySelector(".bootMark"),d=row.querySelector(".bootDetail");
   if(status==="running"){mark.textContent="⟳";row.style.fontWeight="600"}
   else if(status==="done"){mark.textContent="✓";row.style.color="#86efac";row.style.fontWeight="";done.add(step)}
   else if(status==="error"){mark.textContent="✕";row.style.color="#fca5a5";row.style.fontWeight="600"}
   if(detail)d.textContent=" · "+detail;
   document.getElementById("bootProgress").textContent=done.size+" / "+steps.length+" hotovo";
 }
 b.disabled=true;
 try{
  const r=await fetch("/api/bootstrap/portainer/stream",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify(p)});
  if(!r.ok){const raw=await r.text();throw new Error(raw)}
  const reader=r.body.getReader(),decoder=new TextDecoder();let buf="",result=null;
  while(true){
   const {value,done:streamDone}=await reader.read();if(streamDone)break;
   buf+=decoder.decode(value,{stream:true});const lines=buf.split("\n");buf=lines.pop();
   for(const line of lines){
    if(!line.trim())continue;
    const e=JSON.parse(line);
    if(e.type==="progress")update(e.step,e.status||"done",e.detail||"");
    else if(e.type==="error"){update(e.step||"api","error",e.detail||"");throw new Error(e.detail||"Bootstrap selhal")}
    else if(e.type==="result")result=e.result;
   }
  }
  if(!result)throw new Error("Bootstrap skončil bez výsledku.");
  const ok=document.createElement("div");ok.className="ready";ok.style.marginTop="14px";
  ok.innerHTML="✓ První infrastruktura je připravena<br>CONTROL LAN: <strong>"+esc(result.lan_ip)+"</strong><br>Management: <strong>"+esc(result.hub_management_ip)+"</strong><br>Portainer: "+esc(result.portainer_url)+"<br><strong>Jednorázové Portainer admin heslo:</strong> <code>"+esc(result.portainer_admin_password)+"</code>";
  state.appendChild(ok);
  document.getElementById("bootPassword").value="";
  document.getElementById("provSite").value=p.site.toUpperCase();
  document.getElementById("provHubHost").value=result.lan_ip;
  document.getElementById("provHubUser").value=p.ssh_user;
  document.getElementById("provHubEndpoint").value=result.wg_endpoint;
  await loadAppSettings();await loadEndpointSettings();await loadProvisionSites();document.getElementById("provSiteSelect").value=result.site;selectProvisionSite();
 }catch(e){
  const x=document.createElement("div");x.className="error";x.style.marginTop="12px";x.textContent="Bootstrap selhal: "+e.message;state.appendChild(x);
 }finally{b.disabled=false}
}
document.addEventListener("DOMContentLoaded",()=>{
 const p=document.getElementById("bootPassword");
 if(p)p.addEventListener("keydown",e=>{if(e.key==="Enter"){e.preventDefault();bootstrapFirstPortainer()}});
});

async function removeEndpoint(ep,button){
 const state=document.getElementById("endpointSaveState");
 button.disabled=true;if(state)state.textContent="Kontroluji, zda lze server bezpečně odebrat…";
 try{
  const check=await getJson("/api/endpoints/"+ep.id+"/remove-check");
  if(!check.allowed){alert(check.reason||"Server nelze odebrat.");return}
  const hubHost=document.getElementById("provHubHost")?.value||"";
  const hubUser=document.getElementById("provHubUser")?.value||"";
  const hubPassword=document.getElementById("provHubPassword")?.value||"";
  if(!hubHost||!hubUser||!hubPassword){alert("Vyplň v Provisioningu MAIN hub SSH adresu, uživatele a heslo. Heslo se nikam neukládá.");return}
  const msg=check.reason+"\n\nOdebere se endpoint z Portaineru, jeho nastavení v DockerStackMoveru a WireGuard peer z MAIN HUBu. Ubuntu server ani jeho disk se nemažou.\n\nPokračovat?";
  if(!confirm(msg))return;
  const r=await fetch("/api/endpoints/"+ep.id+"/remove",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify({hub_host:hubHost,hub_ssh_user:hubUser,hub_ssh_password:hubPassword})});
  const raw=await r.text();if(!r.ok)throw new Error(raw);
  if(state)state.textContent="✓ "+ep.name+" byl bezpečně odpojen";
  await loadEndpointSettings();await loadReadiness();await loadCapacity();await loadCluster();
 }catch(e){alert("Odebrání serveru selhalo: "+e.message);if(state)state.textContent="Odebrání selhalo"}
 finally{button.disabled=false}
}

let provisionSites=[],provisionHosts=[];
async function loadProvisionSites(){
 const sel=document.getElementById("provSiteSelect");if(!sel)return;
 try{const d=await getJson("/api/provisioning/sites");provisionSites=d.sites||[];sel.innerHTML=provisionSites.map(s=>"<option value='"+esc(s.name)+"'>"+esc(s.name)+" · "+esc(s.lan_cidr)+" · 10.200."+s.management_octet+".0/24</option>").join("");if(!provisionSites.length)sel.innerHTML="<option value=''>Nejdřív založ lokalitu</option>";document.getElementById("siteMgmt").value=d.next_management_octet||2;selectProvisionSite()}catch(e){sel.innerHTML="<option>Lokality nelze načíst</option>"}
}
function toggleSiteEditor(){const e=document.getElementById("provSiteEditor");e.style.display=e.style.display==="none"?"block":"none"}
function selectProvisionSite(){const n=document.getElementById("provSiteSelect")?.value,s=provisionSites.find(x=>x.name===n);if(!s)return;document.getElementById("provSite").value=s.name;document.getElementById("provHubUser").value=(provisionSites.find(x=>x.management_octet===1)||{}).ssh_user||"";document.getElementById("provSelected").innerHTML=""}
async function saveProvisionSite(){
 const p={name:document.getElementById("siteName").value,lan_cidr:document.getElementById("siteLan").value,management_octet:Number(document.getElementById("siteMgmt").value),public_ip:document.getElementById("sitePublicIp").value,ssh_user:document.getElementById("siteSshUser").value};
 const r=await fetch("/api/provisioning/sites",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify(p)});if(!r.ok){alert(await r.text());return}document.getElementById("provSiteEditor").style.display="none";await loadProvisionSites();document.getElementById("provSiteSelect").value=p.name.trim().toUpperCase();selectProvisionSite()
}
async function discoverProvisionHosts(){
 const site=document.getElementById("provSiteSelect").value,box=document.getElementById("provDiscovery");if(!site){alert("Nejdřív založ lokalitu.");return}box.innerHTML="<div class='muted'>Prohledávám LAN na SSH…</div>";
 try{const d=await getJson("/api/provisioning/discovery/"+encodeURIComponent(site));provisionHosts=d.hosts||[];if(!provisionHosts.length){box.innerHTML="<div class='muted'>Nebyl nalezen žádný server s SSH.</div>";return}
 const suffixOptions=Array.from({length:19},(_,n)=>n+11).map(n=>"<option value='"+n+"'>."+n+"</option>").join("");
 box.innerHTML="<div class=\'actions\' style=\'margin-bottom:8px\'><button class=\'secondary\' onclick=\'identifyProvisionHosts()\'>Načíst názvy z Ubuntu</button></div><div class=\'provisionHostList\'>"+provisionHosts.map((h,i)=>"<div class='provisionHost "+(h.provisioned?"disabled":"")+"'><label><input type='checkbox' class='provPick' data-index='"+i+"' "+(h.provisioned?"disabled":"")+"> <strong>"+esc(h.ip)+"</strong></label><span class='muted'>SSH ✓"+(h.provisioned?" · už přidáno":"")+"</span><select class='provRole' data-index='"+i+"' "+(h.provisioned?"disabled":"")+"><option>NODE</option><option>PROXY</option></select><select class='provSuffix' data-index='"+i+"' title='Cílová LAN/WG adresa' "+(h.provisioned?"disabled":"")+"><option value=''>automaticky</option>"+suffixOptions+"</select><input class='provName' data-index='"+i+"' placeholder='hostname – automaticky' "+(h.provisioned?"disabled":"")+"></div>").join("")+"</div>";
 box.querySelectorAll(".provPick,.provRole,.provSuffix,.provName").forEach(e=>e.addEventListener("change",previewProvisionSelection));previewProvisionSelection()
 }catch(e){box.innerHTML="<div class='error'>Discovery selhalo: "+esc(e.message)+"</div>"}
}
async function previewProvisionSelection(){
 const picks=[...document.querySelectorAll(".provPick:checked")],box=document.getElementById("provSelected");if(!picks.length){box.innerHTML="";return}const rows=[],reserved=[];
 for(const p of picks){const i=p.dataset.index,h=provisionHosts[i],role=document.querySelector(".provRole[data-index='"+i+"']").value,name=document.querySelector(".provName[data-index='"+i+"']").value,nodeSuffix=document.querySelector(".provSuffix[data-index='"+i+"']").value;try{const r=await fetch("/api/provisioning/plan",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify({site:document.getElementById("provSiteSelect").value,lan_ip:h.ip,role,name,node_suffix:nodeSuffix,reserved_management_ips:reserved})});if(r.ok){const plan=await r.json();rows.push(plan);reserved.push(plan.management_ip)}}catch(_){}}
 box.innerHTML=rows.length?"<div class='item'><strong>DSM nastaví</strong>"+rows.map(p=>"<div class='provisionPlan'><span>"+esc(p.lan_ip)+"</span><strong>"+esc(p.name)+"</strong><span>"+esc(p.role)+"</span><span>→ "+esc(p.management_ip)+"</span></div>").join("")+"</div>":""
}
async function provisionSelected(){
 const picks=[...document.querySelectorAll(".provPick:checked")],password=document.getElementById("provPassword").value,hubPassword=document.getElementById("provHubPassword").value,state=document.getElementById("provState"),btn=document.getElementById("provButton");
 if(!picks.length){alert("Vyber alespoň jeden server.");return}if(!password||!hubPassword){alert("Vyplň SSH heslo serverů a MAIN HUBu.");return}if(!confirm("Připravit "+picks.length+" serverů?"))return;
 btn.disabled=true;state.innerHTML="";let ok=0;
 for(const pick of picks){
  const i=pick.dataset.index,h=provisionHosts[i],role=document.querySelector(".provRole[data-index='"+i+"']").value,name=document.querySelector(".provName[data-index='"+i+"']").value,nodeSuffix=document.querySelector(".provSuffix[data-index='"+i+"']").value,row=document.createElement("div");
  row.className="item";row.innerHTML="<strong>"+esc(name||h.ip)+"</strong><div class='provServerProgress'></div>";state.appendChild(row);
  const progress=row.querySelector(".provServerProgress");renderProvisionProgress(progress,role);
  try{
   const site=provisionSites.find(s=>s.name===document.getElementById("provSiteSelect").value);let dataDisk="AUTO";
   if(role==="NODE"){const dr=await fetch("/api/provisioning/disks",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify({host:h.ip,ssh_user:site.ssh_user,ssh_password:password})});if(dr.ok){const disks=(await dr.json()).disks||[];if(disks.length===1)dataDisk=disks[0].device;else if(disks.length>1){const choices=disks.map((d,n)=>(n+1)+": "+d.device+" ("+d.size+")").join("\n"),picked=prompt("Server "+h.ip+" má více volných DATA disků:\n\n"+choices+"\n\nZadej číslo disku:","1"),idx=Number(picked)-1;if(!Number.isInteger(idx)||!disks[idx])throw new Error("Výběr DATA disku byl zrušen nebo není platný.");dataDisk=disks[idx].device}}}
   const payload={site:site.name,host:h.ip,role,name,node_suffix:nodeSuffix,data_disk:dataDisk,ssh_user:site.ssh_user,ssh_password:password,hub_ssh_password:hubPassword};
   const resp=await fetch("/api/provisioning/server/stream",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify(payload)});if(!resp.ok)throw new Error(await resp.text());
   const reader=resp.body.getReader(),decoder=new TextDecoder();let buf="",result=null;
   while(true){const z=await reader.read();if(z.done)break;buf+=decoder.decode(z.value,{stream:true});const lines=buf.split("\n");buf=lines.pop();for(const line of lines){if(!line.trim())continue;const e=JSON.parse(line);if(e.type==="progress"){const target=progress.querySelector("#prov-step-"+e.step);if(target){const icon=target.querySelector(".provIcon"),d=target.querySelector(".provDetail");icon.textContent=e.status==="done"?"✓":e.status==="error"?"✕":"◌";icon.style.color=e.status==="done"?"#86efac":e.status==="error"?"#f87171":"";if(d&&e.detail)d.textContent=e.detail}}else if(e.type==="error")throw new Error(e.detail||"Provisioning selhal");else if(e.type==="result")result=e.result}}
   if(!result)throw new Error("Provisioning skončil bez výsledku.");row.querySelector("strong").textContent="✓ "+result.name;ok++;
  }catch(e){row.insertAdjacentHTML("beforeend","<div class='error'>✕ "+esc(e.message)+"</div>")}
 }
 document.getElementById("provPassword").value="";document.getElementById("provHubPassword").value="";btn.disabled=false;await loadEndpointSettings();await loadReadiness();await loadCluster();state.insertAdjacentHTML("afterbegin","<div class='ready'>Hotovo: "+ok+" / "+picks.length+" serverů</div>")
}

async function identifyProvisionHosts(){
 const site=provisionSites.find(s=>s.name===document.getElementById("provSiteSelect").value),password=document.getElementById("provPassword").value;if(!site||!password){alert("Nejdřív vyplň SSH heslo serverů.");return}
 const r=await fetch("/api/provisioning/identify",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify({hosts:provisionHosts.map(h=>h.ip),ssh_user:site.ssh_user,ssh_password:password})});if(!r.ok){alert(await r.text());return}const d=await r.json();
 d.hosts.forEach(h=>{const idx=provisionHosts.findIndex(x=>x.ip===h.ip);if(idx<0||!h.hostname)return;provisionHosts[idx].hostname=h.hostname;const input=document.querySelector(".provName[data-index='"+idx+"']");if(input){input.placeholder=h.hostname;if(!/^(ubuntu|localhost)(-|$)/i.test(h.hostname)&&!input.value)input.value=h.hostname;const label=input.closest(".provisionHost")?.querySelector("label strong");if(label)label.textContent=h.ip+" · "+h.hostname}});
 previewProvisionSelection()
}
