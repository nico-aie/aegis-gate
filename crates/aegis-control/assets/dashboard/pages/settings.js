// Settings page (D-M4-T4.7 + P2 detection-class toggles).
//
// Sections per the spec — Account, Detection classes, Integrations,
// Danger zone. The detection-class section flows through the new
// PUT /api/detectors endpoint (P2), gated by the AuditedMutate
// pipeline (CSRF cookie + audit chain).

let mountEl=null,abortControllers=[],pollTimer=null;
let detectorState=null;

async function fetchJson(url,init){const c=new AbortController();abortControllers.push(c);try{const r=await fetch(url,Object.assign({cache:"no-store",signal:c.signal},init||{}));if(!r.ok)return{ok:false,status:r.status,body:await r.json().catch(()=>null)};return{ok:true,status:r.status,body:await r.json()};}catch(e){if(e.name!=="AbortError")console.error("settings fetch failed",url,e);return{ok:false,status:0,body:null};}}
function setText(slot,text){if(!mountEl)return;const el=mountEl.querySelector(`[data-slot="${slot}"]`);if(el)el.textContent=text;}
function readCookie(name){const parts=document.cookie.split(/;\s*/);for(const p of parts){if(p.startsWith(name+"="))return p.slice(name.length+1);}return null;}

async function refresh(){
  const about=(await fetchJson("/api/about")).body;
  if(about){setText("about-version","v"+(about.version||"?"));setText("about-environment",about.environment||"—");}
  const sess=(await fetchJson("/api/admin/sessions")).body;
  if(sess)setText("sessions-count",`${(sess.sessions||[]).length} active`);
  const bg=(await fetchJson("/api/admin/break-glass")).body;
  if(bg){const pill=mountEl.querySelector('[data-slot="break-glass"]');if(pill){pill.textContent=bg.active?`ACTIVE — ${bg.reason||""}`:"Disabled";pill.dataset.state=bg.active?"err":"ok";}}
  const integ=(await fetchJson("/api/integrations")).body;
  if(integ){const ul=mountEl.querySelector('[data-slot="integrations"]');if(ul){ul.replaceChildren();for(const k of ["grafana_url","alertmanager_url","gitops_repo","prometheus_url"]){const li=document.createElement("li");li.textContent=`${k}: ${integ[k]||"not configured"}`;ul.appendChild(li);}}}
  const dets=(await fetchJson("/api/detectors")).body;
  if(dets)renderDetectors(dets);
  const rt=(await fetchJson("/api/runtime")).body;
  if(rt)renderRuntime(rt);
}

function renderRuntime(rt){
  setText("rt-workers",`${rt.workers} (${rt.workers_mode})`);
  setText("rt-blocking",String(rt.blocking_threads));
  setText("rt-stack",`${rt.stack_size_kb} KiB`);
  setText("rt-host-cpus",String(rt.host_logical_cpus));
  const aff=mountEl.querySelector('[data-slot="rt-affinity"]');
  if(aff){
    if(rt.cpu_affinity_active){aff.textContent="active";aff.dataset.state="ok";}
    else if(rt.cpu_affinity_requested){aff.textContent="requested but feature off";aff.dataset.state="warn";}
    else{aff.textContent="off";aff.dataset.state="ok";}
  }
}

function renderDetectors(state){
  detectorState=state;
  const wrap=mountEl.querySelector('[data-slot="detector-classes"]');
  if(!wrap)return;
  wrap.replaceChildren();
  const labels={sqli:"SQL injection",xss:"Cross-site scripting (XSS)",path_traversal:"Path traversal",ssrf:"Server-side request forgery (SSRF)",header_injection:"Header injection / response splitting",body_abuse:"Body abuse (size, encoding, nesting)",recon:"Reconnaissance probes",brute_force:"Authentication brute force"};
  const locked=new Set(state.locked_classes||[]);
  for(const key of Object.keys(labels)){
    const enabled=!!state.mask[key];
    const isLocked=locked.has(key);
    const id=`detector-${key}`;
    const row=document.createElement("div");
    row.className="aegis-toggle-row";
    const lbl=document.createElement("label");
    lbl.htmlFor=id;
    lbl.textContent=labels[key];
    const input=document.createElement("input");
    input.type="checkbox";
    input.id=id;
    input.dataset.key=key;
    input.checked=enabled;
    input.disabled=isLocked;
    if(isLocked){
      const tip=document.createElement("span");
      tip.className="aegis-pill";
      tip.dataset.state="warn";
      tip.title="Locked by active compliance modes — cannot be disabled.";
      tip.textContent="locked";
      lbl.appendChild(document.createTextNode(" "));
      lbl.appendChild(tip);
    }
    input.addEventListener("change",async()=>{await applyDetectors();});
    row.appendChild(input);
    row.appendChild(lbl);
    wrap.appendChild(row);
  }
  const status=mountEl.querySelector('[data-slot="detector-status"]');
  if(status){
    if((state.compliance_modes||[]).length){
      status.textContent=`Compliance: ${state.compliance_modes.join(", ")} — required classes are locked.`;
    }else{
      status.textContent="Toggle a class to disable its detector on the next request.";
    }
  }
}

async function applyDetectors(){
  if(!mountEl||!detectorState)return;
  const inputs=mountEl.querySelectorAll('[data-slot="detector-classes"] input[type="checkbox"]');
  const body={};
  inputs.forEach((el)=>{body[el.dataset.key]=el.checked;});
  const status=mountEl.querySelector('[data-slot="detector-status"]');
  const csrf=readCookie("aegis_csrf")||"";
  const res=await fetchJson("/api/detectors",{method:"PUT",headers:{"content-type":"application/json","x-csrf-token":csrf},credentials:"same-origin",body:JSON.stringify(body)});
  if(res.ok){
    if(status)status.textContent="Updated.";
    if(res.body)renderDetectors(res.body);
  }else{
    const msg=(res.body&&res.body.message)||`PUT failed (status ${res.status})`;
    if(status)status.textContent=`Error: ${msg}`;
    // Revert UI to last-known good state.
    renderDetectors(detectorState);
  }
}

function renderShell(){
  mountEl.replaceChildren();
  const w=document.createElement("div");w.className="aegis-settings";
  w.innerHTML=`
    <header class="aegis-overview-header"><h1 tabindex="-1">Settings</h1></header>
    <section class="aegis-card" aria-label="Account">
      <h2>Account</h2>
      <dl class="aegis-kv">
        <dt>Build</dt><dd data-slot="about-version">—</dd>
        <dt>Environment</dt><dd data-slot="about-environment">—</dd>
        <dt>Active sessions</dt><dd data-slot="sessions-count">—</dd>
      </dl>
    </section>
    <section class="aegis-card" aria-label="Detection classes">
      <h2>Detection classes</h2>
      <p data-slot="detector-status" class="aegis-banner" role="status">Loading…</p>
      <div data-slot="detector-classes" class="aegis-toggle-grid"></div>
    </section>
    <section class="aegis-card" aria-label="Runtime sizing">
      <h2>Runtime (Layer-1)</h2>
      <p class="aegis-banner" role="note">
        In-process worker thread sizing. Restart-only — change
        <code>runtime:</code> in your YAML config and re-deploy.
      </p>
      <dl class="aegis-kv">
        <dt>Worker threads</dt><dd data-slot="rt-workers">—</dd>
        <dt>Blocking pool</dt><dd data-slot="rt-blocking">—</dd>
        <dt>Stack size</dt><dd data-slot="rt-stack">—</dd>
        <dt>Host logical CPUs</dt><dd data-slot="rt-host-cpus">—</dd>
        <dt>CPU affinity</dt><dd><span class="aegis-pill" data-slot="rt-affinity" data-state="ok">—</span></dd>
      </dl>
    </section>
    <section class="aegis-card" aria-label="Danger zone">
      <h2>Danger zone</h2>
      <p>Break-glass: <span class="aegis-pill" data-slot="break-glass" data-state="ok">Disabled</span></p>
    </section>
    <section class="aegis-card" aria-label="Integrations">
      <h2>Integrations</h2>
      <ul class="aegis-kv-list" data-slot="integrations"></ul>
    </section>
  `;
  mountEl.appendChild(w);
}
export default{mount(el){mountEl=el;renderShell();refresh();pollTimer=setInterval(()=>{if(document.visibilityState==="visible")refresh();},15000);},destroy(){if(pollTimer)clearInterval(pollTimer);pollTimer=null;for(const c of abortControllers)c.abort();abortControllers=[];mountEl=null;detectorState=null;}};
