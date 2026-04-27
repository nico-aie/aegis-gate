// Settings page (D-M4-T4.7).
//
// Five sections per the spec — Account, Authentication policy,
// Dashboard, Integrations, Danger zone. Mutations require M3
// audit-mutation pipeline; v1 surfaces the read paths
// (/api/admin/sessions, /api/admin/break-glass, /api/integrations,
// /api/about) so the page renders meaningful state.

let mountEl=null,abortControllers=[],pollTimer=null;
async function fetchJson(url){const c=new AbortController();abortControllers.push(c);try{const r=await fetch(url,{cache:"no-store",signal:c.signal});if(!r.ok)return null;return await r.json();}catch(e){if(e.name!=="AbortError")console.error("settings fetch failed",url,e);return null;}}
function setText(slot,text){if(!mountEl)return;const el=mountEl.querySelector(`[data-slot="${slot}"]`);if(el)el.textContent=text;}
async function refresh(){
  const about=await fetchJson("/api/about");
  if(about){setText("about-version","v"+(about.version||"?"));setText("about-environment",about.environment||"—");}
  const sess=await fetchJson("/api/admin/sessions");
  if(sess)setText("sessions-count",`${(sess.sessions||[]).length} active`);
  const bg=await fetchJson("/api/admin/break-glass");
  if(bg){const pill=mountEl.querySelector('[data-slot="break-glass"]');if(pill){pill.textContent=bg.active?`ACTIVE — ${bg.reason||""}`:"Disabled";pill.dataset.state=bg.active?"err":"ok";}}
  const integ=await fetchJson("/api/integrations");
  if(integ){const ul=mountEl.querySelector('[data-slot="integrations"]');if(ul){ul.replaceChildren();for(const k of ["grafana_url","alertmanager_url","gitops_repo","prometheus_url"]){const li=document.createElement("li");li.textContent=`${k}: ${integ[k]||"not configured"}`;ul.appendChild(li);}}}
}
function renderShell(){
  mountEl.replaceChildren();
  const w=document.createElement("div");w.className="aegis-settings";
  w.innerHTML=`
    <header class="aegis-overview-header"><h1 tabindex="-1">Settings</h1></header>
    <p class="aegis-banner" role="status">Mutations require M3 audit-mutation pipeline; the page is read-only.</p>
    <section class="aegis-card" aria-label="Account">
      <h2>Account</h2>
      <dl class="aegis-kv">
        <dt>Build</dt><dd data-slot="about-version">—</dd>
        <dt>Environment</dt><dd data-slot="about-environment">—</dd>
        <dt>Active sessions</dt><dd data-slot="sessions-count">—</dd>
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
export default{mount(el){mountEl=el;renderShell();refresh();pollTimer=setInterval(()=>{if(document.visibilityState==="visible")refresh();},15000);},destroy(){if(pollTimer)clearInterval(pollTimer);pollTimer=null;for(const c of abortControllers)c.abort();abortControllers=[];mountEl=null;}};
