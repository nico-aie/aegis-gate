// Tracking page (D-M5-T5.8 + T5.9).
// Six sections (SLO, Active alerts, Upstreams, Cluster peers, Cert
// freshness, GitOps sync) + the Benchmark mode panel slot reserved
// from B-T4.5. Polls /api/tracking/snapshot every 5s; per-section
// drill-ins fetch the dedicated endpoints on demand.

let mountEl=null,abortControllers=[],pollTimer=null,visibilityHandler=null,drawerMod=null,drawer=null;
async function fetchJson(url){const c=new AbortController();abortControllers.push(c);try{const r=await fetch(url,{cache:"no-store",signal:c.signal});if(!r.ok)return null;return await r.json();}catch(e){if(e.name!=="AbortError")console.error("tracking fetch",url,e);return null;}}
function setText(slot,text){if(!mountEl)return;const el=mountEl.querySelector(`[data-slot="${slot}"]`);if(el)el.textContent=text;}
function pillState(el,state){if(el)el.dataset.state=state;}
async function refresh(){
  const snap=await fetchJson("/api/tracking/snapshot");
  if(!snap||!mountEl)return;
  // SLO
  const slos=mountEl.querySelector('[data-slot="slo-rows"]');
  if(slos){slos.replaceChildren();for(const s of (snap.slo&&snap.slo.slis||[])){const li=document.createElement("li");li.textContent=`${s.name}: ${s.current.toFixed(2)} (target ${s.target.toFixed(2)}, budget ${(s.budget_remaining*100).toFixed(0)}%)`;slos.appendChild(li);}}
  // Upstream summary
  const up=snap.upstream||{};
  setText("upstream-summary",`${up.state||"?"} — ${up.healthy_members||0}/${up.total_members||0} healthy`);
  pillState(mountEl.querySelector('[data-slot="upstream-pill"]'),(up.state||"down").toLowerCase());
  // Cluster
  const peers=(snap.cluster&&snap.cluster.peers)||[];
  setText("cluster-summary",peers.length===0?"No peers (single-node)":`${peers.length} peers`);
  // Certs
  const certs=(snap.certs&&snap.certs.certs)||[];
  setText("certs-summary",certs.length===0?"No certs configured":`${certs.length} certs`);
  // GitOps
  const g=snap.gitops||{};
  setText("gitops-summary",g.repo?`${g.repo}@${g.branch||"?"} · ${g.drift?"DRIFT":"in-sync"}`:"Not configured");
  pillState(mountEl.querySelector('[data-slot="gitops-pill"]'),g.drift?"err":"ok");
  // Alerts
  const a=snap.alerts||{firing:[],pending:[],resolved:[]};
  setText("alerts-summary",`${(a.firing||[]).length} firing · ${(a.pending||[]).length} pending`);
}
function setupRenewButton(){
  const btn=mountEl.querySelector('button[data-action="renew-cert"]');
  if(!btn)return;
  btn.addEventListener("click",async()=>{
    if(!drawerMod){drawerMod=(await import("/dashboard/assets/components/drawer.js")).default;}
    if(drawer)drawer.close();
    drawer=drawerMod.open({title:"Cert renewal",body:"Cert renewal flow placeholder — confirm host name in real flow.",onClose:()=>{drawer=null;}});
  });
}
function renderShell(){
  mountEl.replaceChildren();
  const w=document.createElement("div");w.className="aegis-tracking";
  w.innerHTML=`
    <header class="aegis-overview-header"><h1 tabindex="-1">Tracking</h1></header>
    <section class="aegis-overview-grid">
      <article class="aegis-card" aria-label="SLO burn">
        <h2>SLO burn</h2>
        <ul class="aegis-kv-list" data-slot="slo-rows"></ul>
      </article>
      <article class="aegis-card" aria-label="Active alerts">
        <h2>Alerts</h2>
        <p data-slot="alerts-summary">Loading…</p>
      </article>
      <article class="aegis-card aegis-card-wide" aria-label="Upstream pools">
        <h2>Upstreams <span class="aegis-pill" data-slot="upstream-pill" data-state="unknown">—</span></h2>
        <p data-slot="upstream-summary">Loading…</p>
      </article>
      <article class="aegis-card" aria-label="Cluster peers">
        <h2>Cluster</h2>
        <p data-slot="cluster-summary">Loading…</p>
      </article>
      <article class="aegis-card" aria-label="Cert freshness">
        <h2>Certs</h2>
        <p data-slot="certs-summary">Loading…</p>
        <button type="button" data-action="renew-cert">Renew certificate…</button>
      </article>
      <article class="aegis-card aegis-card-wide" aria-label="GitOps sync">
        <h2>GitOps <span class="aegis-pill" data-slot="gitops-pill" data-state="ok">—</span></h2>
        <p data-slot="gitops-summary">Loading…</p>
      </article>
    </section>
  `;
  mountEl.appendChild(w);
}
export default{mount(el){mountEl=el;renderShell();setupRenewButton();refresh();
  pollTimer=setInterval(()=>{if(document.visibilityState==="visible")refresh();},5000);
  visibilityHandler=()=>{if(document.visibilityState==="visible")refresh();};
  document.addEventListener("visibilitychange",visibilityHandler);
},destroy(){if(pollTimer)clearInterval(pollTimer);pollTimer=null;
  for(const c of abortControllers)c.abort();abortControllers=[];
  if(visibilityHandler){document.removeEventListener("visibilitychange",visibilityHandler);visibilityHandler=null;}
  if(drawer){drawer.close();drawer=null;}
  mountEl=null;
}};
