let dnsZone="";
async function loadDnsDomains(){await loadManagedDns();const select=document.getElementById("dnsZone");const box=document.getElementById("dnsRecords");if(!select||!box)return;box.innerHTML='<div class="muted">Načítám domény...</div>';try{const domains=await getJson("/api/dns/domains");select.innerHTML="";domains.forEach(d=>{const o=document.createElement("option");o.value=d.name;o.textContent=d.name;select.appendChild(o)});if(domains.length){dnsZone=select.value;await loadDnsRecords()}else box.innerHTML='<div class="muted">Žádné domény.</div>'}catch(e){box.innerHTML='<div class="error item">'+esc(e.message)+"</div>"}}
async function loadDnsRecords(){const select=document.getElementById("dnsZone");const box=document.getElementById("dnsRecords");dnsZone=select.value;if(!dnsZone)return;box.innerHTML='<div class="muted">Načítám DNS...</div>';try{const rows=await getJson("/api/dns/domains/"+encodeURIComponent(dnsZone)+"/records");box.innerHTML="";const table=document.createElement("table");table.innerHTML="<thead><tr><th>NÁZEV</th><th>TYP</th><th>HODNOTA</th><th>TTL</th><th>AKCE</th></tr></thead>";const body=document.createElement("tbody");rows.forEach(r=>{const tr=document.createElement("tr");tr.innerHTML="<td class='dns-name'>"+esc(r.name)+"</td><td class='dns-type'><strong>"+esc(r.type)+"</strong></td><td class='dns-value'>"+esc(r.content)+"</td><td class='dns-ttl'>"+esc(r.ttl)+"</td><td class='dns-actions'></td>";const actions=tr.lastElementChild;if(hasPerm("dns_write")){const edit=document.createElement("button");edit.className="secondary";edit.textContent=appLang==="en"?"Edit":"Upravit";edit.onclick=()=>editDnsRecord(r);actions.appendChild(edit);if(r.type!=="NS"){const del=document.createElement("button");del.className="danger";del.style.marginLeft="6px";del.textContent="Smazat";del.onclick=()=>deleteDnsRecord(r);actions.appendChild(del)}}body.appendChild(tr)});table.appendChild(body);box.appendChild(table)}catch(e){box.innerHTML='<div class="error item">'+esc(e.message)+"</div>"}}
function dnsForm(record){document.getElementById("dnsRecordId").value=record?record.id:"";document.getElementById("dnsName").value=record?record.name:"";document.getElementById("dnsType").value=record?record.type:"A";document.getElementById("dnsContent").value=record?record.content:"";document.getElementById("dnsTtl").value=record?record.ttl||60:60;document.getElementById("dnsPriority").value=record&&record.priority!=null?record.priority:"";document.getElementById("dnsEditorTitle").textContent=record?"Upravit DNS záznam":"Nový DNS záznam";const editor=document.getElementById("dnsEditor");editor.style.display="block";editor.scrollIntoView({behavior:"smooth",block:"start"})}
function editDnsRecord(r){dnsForm(r)} function newDnsRecord(){dnsForm(null)} function closeDnsEditor(){document.getElementById("dnsEditor").style.display="none"}
async function saveDnsRecord(){const id=document.getElementById("dnsRecordId").value;const payload={name:document.getElementById("dnsName").value.trim(),type:document.getElementById("dnsType").value,content:document.getElementById("dnsContent").value.trim(),ttl:Number(document.getElementById("dnsTtl").value)||60};const p=document.getElementById("dnsPriority").value;if(p!=="")payload.priority=Number(p);const url="/api/dns/domains/"+encodeURIComponent(dnsZone)+"/records"+(id?"/"+encodeURIComponent(id):"");const r=await fetch(url,{method:id?"PUT":"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify(payload)});if(!r.ok){alert("DNS změna selhala: "+await r.text());return}closeDnsEditor();await loadDnsRecords()}
async function deleteDnsRecord(r){if(!confirm("Smazat DNS záznam "+r.name+" "+r.type+"?"))return;const res=await fetch("/api/dns/domains/"+encodeURIComponent(dnsZone)+"/records/"+encodeURIComponent(r.id),{method:"DELETE",headers:{"X-CSRF-Token":csrfToken}});if(!res.ok){alert("Smazání selhalo: "+await res.text());return}await loadDnsRecords()}

async function syncManagedDns(){
 const state=document.getElementById("dnsSyncState");state.textContent="Synchronizuji existující DSM routy s DNS…";
 try{const r=await fetch("/api/dns/sync-routes",{method:"POST",headers:{"X-CSRF-Token":csrfToken}});const raw=await r.text();let d={};try{d=JSON.parse(raw)}catch(_){}
 if(!r.ok)throw new Error(d.detail||raw);const ok=(d.results||[]).filter(x=>x.ok).length,fail=(d.results||[]).length-ok;
 state.textContent="✓ DNS sync: "+ok+" rout OK"+(fail?" · "+fail+" vyžaduje kontrolu":"");await loadDnsRecords()}catch(e){state.textContent="✕ "+String(e.message||e)}
}

async function loadManagedDns(){
 const box=document.getElementById("managedDnsRecords");if(!box)return;
 box.innerHTML='<div class="muted">Kontroluji DSM DNS…</div>';
 try{
  const d=await getJson("/api/dns/managed"),rows=d.items||[];
  if(!rows.length){box.innerHTML='<div class="muted">DSM zatím nespravuje žádné DNS záznamy.</div>';return}
  const table=document.createElement("table");
  table.innerHTML="<thead><tr><th>HOSTNAME</th><th>TYP</th><th>CÍL</th><th>ÚČEL</th><th>STAV</th></tr></thead>";
  const body=document.createElement("tbody");
  const purpose={route:"Aplikační route",anchor:"PROXY anchor","site-anchor":"PROXY anchor",system:"DSM systém"};
  rows.forEach(r=>{const tr=document.createElement("tr"),ok=r.status==="ok";
   tr.innerHTML="<td><strong>"+esc(r.host)+"</strong><div class='muted'>"+esc(r.site||r.stack_name||"")+"</div></td><td>"+esc(r.record_type)+"</td><td>"+esc(r.expected_content||"")+(r.status==="drift"?"<div class='error'>DNS: "+esc(r.actual_content||"")+"</div>":"")+"</td><td><span class='badge "+(r.managed!==false?"running":"")+"'>"+(r.managed!==false?"DSM MANAGED":"EXTERNAL")+"</span><div class='muted'>"+esc(purpose[r.purpose]||r.purpose||"")+"</div></td><td><span class='badge "+(ok?"running":"stopped")+"'>"+(ok?"OK":esc(String(r.status||"").toUpperCase()))+"</span></td>";
   body.appendChild(tr)});
  table.appendChild(body);box.innerHTML="";box.appendChild(table)
 }catch(e){box.innerHTML='<div class="error item">'+esc(e.message)+"</div>"}
}
