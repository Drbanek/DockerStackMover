async function loadProxyCandidates(){
 const select=document.getElementById("stackDomainTarget");if(!select||!selectedStackId)return;
 select.innerHTML='<option value="">Načítám…</option>';
 try{const d=await getJson("/api/stacks/"+selectedStackId+"/proxy/candidates");select.innerHTML="";
  (d.candidates||[]).forEach(c=>{const o=document.createElement("option");o.value=c.service+"|"+c.container_port;o.textContent=c.service+":"+c.container_port+(c.container?" · "+c.container:"");select.appendChild(o)});
  if(!select.options.length)select.innerHTML='<option value="">Nebyla nalezena služba s TCP portem</option>';
 }catch(e){select.innerHTML='<option value="">Chyba načtení služeb</option>'}
}
async function saveStackDomain(){
 if(!selectedStackId)return;
 const host=(document.getElementById("stackDomainHost").value||"").trim(),target=(document.getElementById("stackDomainTarget").value||""),state=document.getElementById("stackDomainState");
 if(!host){state.textContent="Zadej doménu.";return}
 const parts=target.split("|"),payload={host:host};if(parts.length===2){payload.service=parts[0];payload.container_port=Number(parts[1])}
 state.textContent="Přidávám směrování, provádím redeploy a synchronizuji Traefik…";
 try{
  const r=await fetch("/api/stacks/"+selectedStackId+"/proxy/routes",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify(payload)});
  const raw=await r.text();let d={};try{d=JSON.parse(raw)}catch(_){}
  if(!r.ok)throw new Error(d.detail||raw||("HTTP "+r.status));
  state.textContent="✓ "+d.host+" → "+d.service+":"+d.container_port+" · HTTPS";
  document.getElementById("stackDomainHost").value="";
  await showDetail(selectedStackId);
 }catch(e){state.textContent="✕ "+String(e.message||e)}
}
async function deleteStackRoute(routeId,host){
 if(!selectedStackId||!confirm("Smazat směrování "+host+"?"))return;
 const state=document.getElementById("stackDomainState");state.textContent="Mažu směrování…";
 try{const r=await fetch("/api/stacks/"+selectedStackId+"/proxy/routes/"+Number(routeId),{method:"DELETE",headers:{"X-CSRF-Token":csrfToken}});if(!r.ok)throw new Error(await r.text());state.textContent="✓ Směrování smazáno.";await showDetail(selectedStackId)}catch(e){state.textContent="✕ "+String(e.message||e)}
}
async function adoptLegacyRoute(host){
 if(!selectedStackId)return;
 const state=document.getElementById("stackDomainState");state.textContent="Přebírám "+host+" do DSM správy…";
 try{const r=await fetch("/api/stacks/"+selectedStackId+"/proxy/adopt",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify({host:host})});const raw=await r.text();let d={};try{d=JSON.parse(raw)}catch(_){}
  if(!r.ok)throw new Error(d.detail||raw||("HTTP "+r.status));state.textContent="✓ "+d.host+" převzato → "+d.service+":"+d.container_port+" · backend "+d.backend_port;await showDetail(selectedStackId)
 }catch(e){state.textContent="✕ "+String(e.message||e)}
}
async function syncStackProxy(stackId,domainsBox){try{const r=await fetch("/api/stacks/"+Number(stackId)+"/proxy/sync",{method:"POST",headers:{"X-CSRF-Token":csrfToken}});const raw=await r.text();if(!r.ok)throw new Error(raw);const d=JSON.parse(raw);if(d.configured){const x=document.createElement("div");x.className="item checkOk";x.textContent="✓ Traefik synchronizován · "+d.site+" · backend "+d.lan_ip;domainsBox.appendChild(x)}}catch(e){const x=document.createElement("div");x.className="item checkError";x.textContent="× Traefik sync: "+e.message;domainsBox.appendChild(x)}}
async function loadStacks(){const table=document.getElementById("stacks");table.innerHTML='<tr><td colspan="4">Načítám...</td></tr>';try{const stacks=await getJson("/api/inventory");table.innerHTML="";stacks.forEach(function(stack){const tr=document.createElement("tr");const status=stack.status===1?'<span class="badge running">Running</span>':'<span class="badge stopped">Stopped</span>';tr.innerHTML="<td><strong>"+esc(stack.name)+"</strong></td><td>"+esc(stack.endpoint)+"</td><td>"+status+"</td><td><button onclick=\"showDetail("+Number(stack.id)+")\">Detail</button></td>";table.appendChild(tr)})}catch(error){table.innerHTML='<tr><td colspan="4" class="error">'+esc(error.message)+"</td></tr>"}}
async function showDetail(id){loadAdvisor(id);selectedStackId=Number(id);document.getElementById("movePanel").style.display="none";const detail=document.getElementById("detail");detail.style.display="block";document.getElementById("detailTitle").textContent="Načítám...";try{const data=await getJson("/api/stacks/"+Number(id)+"/detail");selectedDetail=data;document.getElementById("detailTitle").textContent="Detail: "+data.stack.name;document.getElementById("node").textContent=data.stack.endpoint;document.getElementById("containerCount").textContent=data.containers.length;document.getElementById("volumeCount").textContent=data.volumes.length;const domains=document.getElementById("domains");domains.innerHTML="";const domainInput=document.getElementById("stackDomainHost");if(domainInput)domainInput.value="";if(data.domains.length===0)domains.innerHTML='<div class="muted">Žádné směrování</div>';else {data.domains.forEach(function(domain){const item=document.createElement("div");item.className="item domain";const label=document.createElement("span");label.textContent=(domain.https?"https":"http")+"://"+domain.host+" → "+(domain.managed&&domain.service?domain.service+":"+domain.container_port:"backend "+domain.port+(domain.service?" · "+domain.service:""));item.appendChild(label);if(domain.managed&&domain.id){const del=document.createElement("button");del.className="danger";del.style.marginLeft="10px";del.textContent="Smazat";del.onclick=()=>deleteStackRoute(domain.id,domain.host);item.appendChild(del)}else if(domain.legacy){const adopt=document.createElement("button");adopt.className="secondary";adopt.style.marginLeft="10px";adopt.textContent="Převzít do správy";adopt.onclick=()=>adoptLegacyRoute(domain.host);item.appendChild(adopt)}domains.appendChild(item)});await syncStackProxy(id,domains)}await loadProxyCandidates();const containers=document.getElementById("containers");containers.innerHTML="";data.containers.forEach(function(container){const item=document.createElement("div");item.className="item";const title=document.createElement("strong");title.textContent=container.name;const image=document.createElement("div");image.className="muted";image.textContent=container.image;const status=document.createElement("div");status.textContent=container.status;item.appendChild(title);item.appendChild(image);item.appendChild(status);containers.appendChild(item)});const volumes=document.getElementById("volumes");volumes.innerHTML="";if(data.volumes.length===0)volumes.innerHTML='<div class="muted">Žádné named volumes</div>';else data.volumes.forEach(function(volume){const item=document.createElement("div");item.className="item";const title=document.createElement("strong");title.textContent=volume.name;const driver=document.createElement("div");driver.className="muted";driver.textContent="Driver: "+volume.driver;item.appendChild(title);item.appendChild(driver);volumes.appendChild(item)});detail.scrollIntoView({behavior:"smooth"})}catch(error){document.getElementById("detailTitle").textContent="Chyba";document.getElementById("containers").innerHTML='<div class="error">'+esc(error.message)+"</div>"}}
async function openMove(){if(!selectedStackId||!selectedDetail)return;const panel=document.getElementById("movePanel");panel.style.display="block";document.getElementById("moveTitle").textContent="Přesunout: "+selectedDetail.stack.name;document.getElementById("moveSource").textContent=selectedDetail.stack.endpoint;document.getElementById("preflight").innerHTML="";const select=document.getElementById("targetSelect");select.innerHTML='<option>Načítám...</option>';try{const data=await getJson("/api/stacks/"+selectedStackId+"/targets");select.innerHTML="";if(data.targets.length===0){const option=document.createElement("option");option.textContent="Žádný dostupný cílový NODE";option.value="";select.appendChild(option)}else data.targets.forEach(function(target){const option=document.createElement("option");option.value=target.id;option.textContent=target.name;select.appendChild(option)});panel.scrollIntoView({behavior:"smooth"})}catch(error){select.innerHTML="";document.getElementById("preflight").innerHTML='<div class="error item">'+esc(error.message)+"</div>"}}
function closeMove(){document.getElementById("movePanel").style.display="none"}
const preflightSteps=[["source_target","Zdroj a cíl"],["target_ready","Připravenost cíle"],["stack_name","Kolize názvu stacku"],["ports","Kolize portů"],["volumes","Kolize volumes"],["bind_mounts","Bind mounty"],["proxy_lan_ip","Proxy LAN IP"],["proxy_site","Proxy lokality"],["data_capacity","Kapacita DATA /srv"]];
function renderPreflightProgress(box){
 box.innerHTML="<div style='margin-top:12px'><strong>Průběh pre-flight kontroly</strong></div>"+preflightSteps.map((x,i)=>"<div id='preflight-step-"+x[0]+"' style='padding:3px 0'><span class='preflightIcon' style='display:inline-block;width:22px'>"+(i===0?"◌":"○")+"</span><span>"+esc(x[1])+"</span><small class='muted preflightDetail' style='margin-left:8px'></small></div>").join("");
}
function updatePreflightStep(id,status,detail){
 const row=document.getElementById("preflight-step-"+id);if(!row)return;
 const icon=row.querySelector(".preflightIcon"),d=row.querySelector(".preflightDetail");
 icon.textContent=status==="done"?"✓":status==="error"?"✕":status==="warning"?"!":"◌";
 icon.style.color=status==="done"?"#86efac":status==="error"?"#f87171":status==="warning"?"#fbbf24":"";
 if(d&&detail)d.textContent=detail;
 if(status==="done"||status==="warning"){let n=row.nextElementSibling;if(n){const ni=n.querySelector(".preflightIcon");if(ni&&ni.textContent==="○")ni.textContent="◌"}}
}
async function runPreflight(){
 const targetId=Number(document.getElementById("targetSelect").value),box=document.getElementById("preflight");
 if(!targetId){box.innerHTML='<div class="error item">Vyber cílový NODE.</div>';return}
 renderPreflightProgress(box);
 try{
  const r=await fetch("/api/stacks/"+selectedStackId+"/preflight-v2/"+targetId+"/stream",{cache:"no-store"});
  if(!r.ok)throw new Error(await r.text());
  const reader=r.body.getReader(),decoder=new TextDecoder();let buf="",data=null;
  while(true){const z=await reader.read();if(z.done)break;buf+=decoder.decode(z.value,{stream:true});const lines=buf.split("\\n");buf=lines.pop();for(const line of lines){if(!line.trim())continue;const e=JSON.parse(line);if(e.type==="progress")updatePreflightStep(e.step,e.status,e.detail||"");else if(e.type==="error")throw new Error(e.detail||"Pre-flight selhal");else if(e.type==="result")data=e.result}}
  if(!data)throw new Error("Pre-flight skončil bez výsledku.");
  const result=document.createElement("div");result.style.marginTop="10px";result.className=data.ready?"ready":"notReady";
  result.textContent=data.ready?"✓ Připraveno k migraci. Můžeš spustit bezpečný přesun.":"✕ Migrace zatím není připravena. Nejdřív oprav neúspěšné kontroly.";box.appendChild(result);
  if(data.ready){const actions=document.createElement("div");actions.className="actions";const migrate=document.createElement("button");migrate.className="success";migrate.textContent="Zahájit bezpečný přesun";migrate.onclick=function(){startMigration(targetId)};actions.appendChild(migrate);box.appendChild(actions)}
 }catch(error){const err=document.createElement("div");err.className="error";err.style.marginTop="8px";err.textContent=error.message;box.appendChild(err)}
}
