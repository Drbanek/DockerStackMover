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
  state.textContent="✓ "+d.host+" → "+d.service+":"+d.container_port+" · čekám na veřejné DNS, pak se publikuje Traefik routa a vydá certifikát";
  document.getElementById("stackDomainHost").value="";
  await showDetail(selectedStackId);
 }catch(e){if(state)state.textContent="✕ "+String(e.message||e);else alert("Nové vydání certifikátu selhalo: "+String(e.message||e))}
}
async function deleteStackRoute(routeId,host){
 if(!selectedStackId||!confirm("Smazat směrování "+host+"?"))return;
 const state=document.getElementById("stackDomainState");state.textContent="Mažu směrování…";
 try{const r=await fetch("/api/stacks/"+selectedStackId+"/proxy/routes/"+Number(routeId),{method:"DELETE",headers:{"X-CSRF-Token":csrfToken}});if(!r.ok)throw new Error(await r.text());state.textContent="✓ Směrování smazáno.";await showDetail(selectedStackId)}catch(e){if(state)state.textContent="✕ "+String(e.message||e);else alert("Nové vydání certifikátu selhalo: "+String(e.message||e))}
}
async function adoptLegacyRoute(host){
 if(!selectedStackId)return;
 const state=document.getElementById("stackDomainState");state.textContent="Přebírám "+host+" do DSM správy…";
 try{const r=await fetch("/api/stacks/"+selectedStackId+"/proxy/adopt",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify({host:host})});const raw=await r.text();let d={};try{d=JSON.parse(raw)}catch(_){}
  if(!r.ok)throw new Error(d.detail||raw||("HTTP "+r.status));state.textContent="✓ "+d.host+" převzato → "+d.service+":"+d.container_port+" · backend "+d.backend_port;await showDetail(selectedStackId)
 }catch(e){if(state)state.textContent="✕ "+String(e.message||e);else alert("Nové vydání certifikátu selhalo: "+String(e.message||e))}
}
async function syncStackProxy(stackId,domainsBox){try{const r=await fetch("/api/stacks/"+Number(stackId)+"/proxy/sync",{method:"POST",headers:{"X-CSRF-Token":csrfToken}});const raw=await r.text();if(!r.ok)throw new Error(raw);const d=JSON.parse(raw);if(d.configured){const x=document.createElement("div");x.className="item checkOk";x.textContent="✓ Traefik synchronizován · "+d.site+" · backend "+d.lan_ip;domainsBox.appendChild(x)}}catch(e){const x=document.createElement("div");x.className="item checkError";x.textContent="× Traefik sync: "+e.message;domainsBox.appendChild(x)}}
async function loadStacks(){const table=document.getElementById("stacks");table.innerHTML='<tr><td colspan="5">Načítám...</td></tr>';try{const stacks=await getJson("/api/inventory");table.innerHTML="";stacks.forEach(function(stack){const tr=document.createElement("tr");const status=stack.status===1?'<span class="badge running">Running</span>':'<span class="badge stopped">Stopped</span>';tr.innerHTML="<td><strong>"+esc(stack.name)+"</strong></td><td>"+esc(stack.endpoint)+"</td><td>"+status+"</td><td class='stackSsl' data-stack='"+Number(stack.id)+"'><span class='muted'>…</span></td><td><button onclick=\"showDetail("+Number(stack.id)+")\">Detail</button></td>";table.appendChild(tr)});loadCertOverview(false)}catch(error){table.innerHTML='<tr><td colspan="5" class="error">'+esc(error.message)+"</td></tr>"}}
async function showDetail(id){loadAdvisor(id);selectedStackId=Number(id);document.getElementById("movePanel").style.display="none";const detail=document.getElementById("detail");detail.style.display="block";document.getElementById("detailTitle").textContent="Načítám...";try{const data=await getJson("/api/stacks/"+Number(id)+"/detail");selectedDetail=data;document.getElementById("detailTitle").textContent="Detail: "+data.stack.name;document.getElementById("node").textContent=data.stack.endpoint;document.getElementById("containerCount").textContent=data.containers.length;document.getElementById("volumeCount").textContent=data.volumes.length;const domains=document.getElementById("domains");domains.innerHTML="";const domainInput=document.getElementById("stackDomainHost");if(domainInput)domainInput.value="";if(data.domains.length===0)domains.innerHTML='<div class="muted">Žádné směrování</div>';else {data.domains.forEach(function(domain){const item=document.createElement("div");item.className="item domain";const label=document.createElement("span");label.textContent=(domain.https?"https":"http")+"://"+domain.host+" → "+(domain.managed&&domain.service?domain.service+":"+domain.container_port:"backend "+domain.port+(domain.service?" · "+domain.service:""));item.appendChild(label);if(domain.managed&&domain.id){const del=document.createElement("button");del.className="danger";del.style.marginLeft="10px";del.textContent="Smazat";del.onclick=()=>deleteStackRoute(domain.id,domain.host);item.appendChild(del)}else if(domain.legacy){const adopt=document.createElement("button");adopt.className="secondary";adopt.style.marginLeft="10px";adopt.textContent="Převzít do správy";adopt.onclick=()=>adoptLegacyRoute(domain.host);item.appendChild(adopt)}const cert=document.createElement("div");cert.className="certInfo muted";cert.dataset.host=String(domain.host||"").toLowerCase();cert.textContent="Certifikát: načítám…";item.appendChild(cert);domains.appendChild(item)});await syncStackProxy(id,domains);loadStackCerts(id)}await loadProxyCandidates();const containers=document.getElementById("containers");containers.innerHTML="";data.containers.forEach(function(container){const item=document.createElement("div");item.className="item";const title=document.createElement("strong");title.textContent=container.name;const image=document.createElement("div");image.className="muted";image.textContent=container.image;const status=document.createElement("div");status.textContent=container.status;item.appendChild(title);item.appendChild(image);item.appendChild(status);containers.appendChild(item)});const volumes=document.getElementById("volumes");volumes.innerHTML="";if(data.volumes.length===0)volumes.innerHTML='<div class="muted">Žádné named volumes</div>';else data.volumes.forEach(function(volume){const item=document.createElement("div");item.className="item";const title=document.createElement("strong");title.textContent=volume.name;const driver=document.createElement("div");driver.className="muted";driver.textContent="Driver: "+volume.driver;item.appendChild(title);item.appendChild(driver);volumes.appendChild(item)});detail.scrollIntoView({behavior:"smooth"})}catch(error){document.getElementById("detailTitle").textContent="Chyba";document.getElementById("containers").innerHTML='<div class="error">'+esc(error.message)+"</div>"}}
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

let certPollTimer=null;
function fmtCertDate(v){if(!v)return"?";const d=new Date(v);return isNaN(d)?String(v):d.toLocaleString("cs-CZ",{day:"numeric",month:"numeric",year:"numeric",hour:"2-digit",minute:"2-digit"})}
function renderCertInfo(box,c,stackId){
 box.innerHTML="";box.className="certInfo";
 const text=document.createElement("span");
 if(c.not_after&&c.valid){
  const iss=String(c.issuer||""),io=(iss.match(/O\s*=\s*([^,\/]+)/)||[])[1]||"",icn=(iss.match(/CN\s*=\s*([^,\/]+)/)||[])[1]||"",issuer=((io?io.trim()+" ":"")+icn.trim()).trim()||iss;
  const days=Number(c.days_left);
  text.className=days<14?"certWarn":"certOk";
  text.textContent="🔒 "+issuer+" · vydán "+fmtCertDate(c.not_before)+" · platný do "+fmtCertDate(c.not_after)+" ("+days+" dní)";
 }else if(c.not_after){
  text.className="certBad";
  text.textContent="⚠ Neplatný certifikát"+(c.default_cert?" (Traefik default – Let's Encrypt nevydal)":"")+" · "+(c.verify||"")+" · platný do "+fmtCertDate(c.not_after);
 }else{text.className="certBad";text.textContent="⚠ Certifikát nenalezen"}
 box.appendChild(text);
 const task=c.task;
 if(task&&task.state){const t=document.createElement("div");t.className=task.state==="error"?"certBad":task.state==="ok"?"certOk":"muted";t.textContent=(task.state==="running"?"⏳ ":task.state==="ok"?"✓ ":"✕ ")+task.message;box.appendChild(t)}
 const running=task&&task.state==="running";
 const btn=document.createElement("button");btn.className="secondary";btn.dataset.permission="migrations";btn.style.marginLeft="10px";btn.textContent="Vygenerovat nový";btn.disabled=!!running;
 if(typeof hasPerm==="function"&&!hasPerm("migrations"))btn.style.display="none";btn.onclick=()=>renewStackCert(stackId,c.host);box.appendChild(btn);
 return running;
}
async function loadStackCerts(stackId){
 clearTimeout(certPollTimer);
 const boxes=Array.from(document.querySelectorAll("#domains .certInfo"));if(!boxes.length)return;
 try{
  const d=await getJson("/api/stacks/"+Number(stackId)+"/proxy/certs");
  if(Number(stackId)!==Number(selectedStackId))return;
  let running=false;
  boxes.forEach(box=>{const c=(d.certs||[]).find(x=>x.host===box.dataset.host);if(c){if(renderCertInfo(box,c,stackId))running=true}else{box.textContent="Certifikát: bez údajů"}});
  if(running)certPollTimer=setTimeout(()=>loadStackCerts(stackId),10000);
 }catch(e){boxes.forEach(b=>{b.className="certInfo certBad";b.textContent="Certifikát: "+String(e.message||e)})}
}
async function renewStackCert(stackId,host){
 if(!confirm("Vygenerovat nový certifikát pro "+host+"?\n\nUložený certifikát se odstraní z acme.json (vytvoří se záloha) a Traefik na této lokalitě se restartuje (krátký výpadek všech webů za touto PROXY).\nLet's Encrypt povoluje max. 5 stejných certifikátů týdně."))return;
 const state=Number(stackId)===Number(selectedStackId)?document.getElementById("stackDomainState"):null;if(state)state.textContent="Spouštím nové vydání certifikátu pro "+host+"…";
 try{const r=await fetch("/api/stacks/"+Number(stackId)+"/proxy/certs/renew",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify({host:host})});const raw=await r.text();let d={};try{d=JSON.parse(raw)}catch(_){}
  if(!r.ok)throw new Error(d.detail||raw||("HTTP "+r.status));if(state)state.textContent="⏳ "+host+": "+((d.task||{}).message||"probíhá");if(selectedStackId)loadStackCerts(selectedStackId);loadCertOverview(false)
 }catch(e){if(state)state.textContent="✕ "+String(e.message||e);else alert("Nové vydání certifikátu selhalo: "+String(e.message||e))}
}

/* ---- SSL overview: dashboard card, dashboard stack cards, stack table column ---- */
let certOverview=null,certOverviewPromise=null,certOverviewTimer=null;
function certIssuer(c){const iss=String(c.issuer||""),io=(iss.match(/O\s*=\s*([^,\/]+)/)||[])[1]||"",icn=(iss.match(/CN\s*=\s*([^,\/]+)/)||[])[1]||"";return((io?io.trim()+" ":"")+icn.trim()).trim()||iss}
function certLevel(c){if(c.task&&c.task.state==="running")return"pending";if(!c.valid)return"bad";if(c.days_left!=null&&c.days_left<14)return"warn";return"ok"}
function certShort(c){if(c.task&&c.task.state==="running")return"⏳ "+c.task.message;if(c.error)return"✕ "+c.error;if(!c.not_after)return"⚠ certifikát nenalezen";if(!c.valid)return"⚠ neplatný"+(c.default_cert?" (Traefik default)":"");return"🔒 do "+fmtCertDate(c.not_after).split(" ")[0]+" ("+c.days_left+" dní)"}
async function loadCertOverview(force){
 if(certOverviewPromise&&!force)return certOverviewPromise;
 const box=document.getElementById("dashboardCerts");if(box&&(force||!certOverview))box.innerHTML='<div class="muted">Kontroluji certifikáty na PROXY serverech…</div>';
 certOverviewPromise=(async()=>{
  try{certOverview=await getJson("/api/proxy/certs"+(force?"?refresh=1":""));renderCertOverview()}
  catch(e){if(box)box.innerHTML='<div class="error item">'+esc(e.message||e)+'</div>';document.querySelectorAll(".stackSsl").forEach(td=>td.innerHTML="<span class='certBad'>chyba</span>")}
  finally{certOverviewPromise=null}
 })();
 return certOverviewPromise;
}
function renderCertOverview(){
 const certs=(certOverview&&certOverview.certs)||[];
 const box=document.getElementById("dashboardCerts");
 if(box){
  if(!certs.length){box.innerHTML='<div class="muted">Žádné domény se SSL.</div>'}
  else{
   const bad=certs.filter(c=>certLevel(c)==="bad").length,warn=certs.filter(c=>certLevel(c)==="warn").length;
   let html="<div class='certSummary'><span class='certOk'>"+(certs.length-bad-warn)+" v pořádku</span>"+(warn?" · <span class='certWarn'>"+warn+" brzy vyprší</span>":"")+(bad?" · <span class='certBad'>"+bad+" neplatných</span>":"")+"<span class='muted'> · kontrola "+fmtCertDate(certOverview.checked_at)+"</span></div>";
   html+="<div class='tableWrap'><table class='certTable'><thead><tr><th>DOMÉNA</th><th>STACK</th><th>VYDAVATEL</th><th>VYDÁN</th><th>PLATNÝ DO</th><th>ZBÝVÁ</th><th>STAV</th><th></th></tr></thead><tbody>";
   certs.forEach((c,i)=>{const lvl=certLevel(c);const stateTxt=lvl==="pending"?"⏳ "+esc(c.task.message):lvl==="bad"?"⚠ "+(c.error?esc(c.error):c.default_cert?"Traefik default – nevydán":esc(c.verify||"neplatný")):lvl==="warn"?"brzy vyprší":"✓ platný";const taskNote=c.task&&c.task.state==="error"?"<div class='certBad'>✕ "+esc(c.task.message)+"</div>":c.task&&c.task.state==="ok"?"<div class='certOk'>✓ "+esc(c.task.message)+"</div>":"";
    const real=c.not_after&&!c.default_cert;html+="<tr class='cert-"+lvl+"'><td><a href='https://"+esc(c.host)+"' target='_blank' rel='noopener'>"+esc(c.host)+"</a></td><td><a href='#' data-open-stack='"+Number(c.stack_id||0)+"'>"+esc(c.stack||"—")+"</a></td><td>"+esc(real?certIssuer(c):"—")+"</td><td>"+esc(real?fmtCertDate(c.not_before):"—")+"</td><td>"+esc(real?fmtCertDate(c.not_after):"—")+"</td><td>"+(real&&c.days_left!=null?esc(c.days_left)+" dní":"—")+"</td><td class='cert"+(lvl==="ok"?"Ok":lvl==="warn"?"Warn":lvl==="bad"?"Bad":"Pending")+"'>"+stateTxt+taskNote+"</td><td>"+(c.stack_id&&(typeof hasPerm!=="function"||hasPerm("migrations"))?"<button class='secondary' data-renew='"+i+"'"+(lvl==="pending"?" disabled":"")+">Vygenerovat nový</button>":"")+"</td></tr>"});
   html+="</tbody></table></div>";
   if(certOverview.errors&&certOverview.errors.length)html+="<div class='error'>"+certOverview.errors.map(esc).join("<br>")+"</div>";
   box.innerHTML=html;
   box.querySelectorAll("[data-renew]").forEach(b=>{const c=certs[Number(b.dataset.renew)];b.onclick=()=>renewStackCert(c.stack_id,c.host)});
   box.querySelectorAll("[data-open-stack]").forEach(a=>{a.onclick=async ev=>{ev.preventDefault();const id=Number(a.dataset.openStack);if(!id)return;showTab("migrations",document.getElementById("tabButtonMigrations"));await showDetail(id)}});
  }
 }
 // dashboard stack cards: colour domain pills and add expiry line
 document.querySelectorAll(".stackCard .stackDomains .domain[data-host]").forEach(p=>{const c=certs.find(x=>x.host===p.dataset.host);p.classList.remove("cert-ok","cert-warn","cert-bad","cert-pending");if(!c)return;p.classList.add("cert-"+certLevel(c));p.title=certShort(c)});
 document.querySelectorAll(".stackCard[data-stack]").forEach(card=>{const own=certs.filter(c=>Number(c.stack_id)===Number(card.dataset.stack));let line=card.querySelector(".stackSslLine");if(!own.length){if(line)line.remove();return}if(!line){line=document.createElement("div");line.className="stackSslLine";card.appendChild(line)}line.innerHTML=stackSslSummary(own)});
 // stack table column
 document.querySelectorAll(".stackSsl[data-stack]").forEach(td=>{const own=certs.filter(c=>Number(c.stack_id)===Number(td.dataset.stack));td.innerHTML=own.length?stackSslSummary(own):"<span class='muted'>—</span>"});
 clearTimeout(certOverviewTimer);
 if(certs.some(c=>c.task&&c.task.state==="running"))certOverviewTimer=setTimeout(()=>loadCertOverview(false),10000);
}
function stackSslSummary(own){
 const lvls=own.map(certLevel);const worst=lvls.includes("bad")?"bad":lvls.includes("warn")?"warn":lvls.includes("pending")?"pending":"ok";
 const cls=worst==="ok"?"certOk":worst==="warn"?"certWarn":worst==="bad"?"certBad":"muted";
 if(own.length===1)return"<span class='"+cls+"' title='"+esc(own[0].host)+"'>"+esc(certShort(own[0]))+"</span>";
 const valid=own.filter(c=>c.days_left!=null&&c.valid).map(c=>c.days_left);const min=valid.length?Math.min.apply(null,valid):null;
 const badCount=lvls.filter(l=>l==="bad").length;
 return"<span class='"+cls+"' title='"+esc(own.map(c=>c.host+": "+certShort(c)).join("\n"))+"'>"+(badCount?"⚠ "+badCount+"/"+own.length+" neplatné":"🔒 "+own.length+" domén")+(min!=null?" · nejbližší za "+min+" dní":"")+"</span>";
}
