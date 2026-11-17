#!/usr/bin/env python3
"""Web demo.  python app.py  ->  http://localhost:5000"""
import random
import sys
from pathlib import Path

from flask import Flask, jsonify, request

sys.path.insert(0, str(Path(__file__).resolve().parent))

from phishcheck.checker import MODES, PhishChecker  # noqa: E402
from phishcheck.synthetic import TEMPLATES, _ctx  # noqa: E402

app = Flask(__name__)
checker = PhishChecker()

EXAMPLES = {
    "Classic phishing": TEMPLATES["phish_classic"][0],
    "AI-written phishing": TEMPLATES["phish_ai"][0],
    "CEO gift-card scam": TEMPLATES["phish_ai"][1],
    "Hidden prompt injection": TEMPLATES["injection"][0],
    "Injection: note to AI": TEMPLATES["injection"][2],
    "Normal: GitHub": TEMPLATES["legit"][0],
    "Normal: real password reset": TEMPLATES["legit"][3],
    "Normal: newsletter": TEMPLATES["legit"][4],
}


@app.get("/api/status")
def status():
    return jsonify(model=checker.model is not None, llm=checker.llm.available, llm_model=checker.llm.model)


@app.get("/api/example/<name>")
def example(name):
    t = EXAMPLES.get(name)
    if not t:
        return jsonify(error="unknown example"), 404
    r = random.Random()
    return jsonify(raw=t(_ctx(r), r))


@app.post("/api/check")
def check():
    d = request.get_json(force=True, silent=True) or {}
    raw = (d.get("email") or "").strip()
    mode = d.get("mode", "full")
    if not raw:
        return jsonify(error="Paste an email first."), 400
    if len(raw) > 200_000:
        return jsonify(error="Email too large (200 KB max)."), 400
    if mode not in MODES:
        return jsonify(error=f"mode must be one of {MODES}"), 400
    return jsonify(checker.check(raw, mode=mode).to_dict())


@app.get("/")
def index():
    opts = "".join(f'<button class="ex" data-n="{n}">{n}</button>' for n in EXAMPLES)
    return PAGE.replace("{{EXAMPLES}}", opts)


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phishing Checker</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#16181d;--mute:#626875;--line:#e3e6eb;--red:#c62828;--amber:#b26a00;--green:#1b7f3b;--violet:#6a3fb5;--accent:#1f4fd1}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--ink)}
header{padding:22px 28px 6px}h1{margin:0;font-size:22px}header p{margin:4px 0 0;color:var(--mute)}
main{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:20px;padding:16px 28px 40px}
@media(max-width:900px){main{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px}
textarea{width:100%;min-height:380px;border:1px solid var(--line);border-radius:8px;padding:12px;font:13px/1.45 ui-monospace,Menlo,Consolas,monospace;resize:vertical}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px}
select,button{font:inherit;border-radius:8px;border:1px solid var(--line);padding:8px 12px;background:#fff;cursor:pointer}
button.go{background:var(--accent);color:#fff;border-color:var(--accent);font-weight:600;padding:9px 20px}
button.go:disabled{opacity:.6;cursor:wait}
.ex{font-size:12.5px;padding:5px 9px;color:var(--mute)}.ex:hover{color:var(--ink);border-color:#bbb}
.small{font-size:12.5px;color:var(--mute)}
.verdict{display:flex;align-items:center;gap:14px}.badge{font-weight:700;font-size:20px;padding:6px 14px;border-radius:8px;color:#fff;text-transform:uppercase;letter-spacing:.03em}
.phishing{background:var(--red)}.suspicious{background:var(--amber)}.legitimate{background:var(--green)}.error{background:#777}
.bar{height:8px;background:#eceef2;border-radius:4px;overflow:hidden;margin:12px 0 4px}.bar i{display:block;height:100%}
h3{font-size:14px;margin:20px 0 8px;text-transform:uppercase;letter-spacing:.05em;color:var(--mute)}
ul{margin:0;padding-left:20px}li{margin:4px 0}
.inj{border:1px solid #d8c8f2;background:#f7f2ff;border-radius:8px;padding:12px;margin-top:14px}.inj b{color:var(--violet)}
.flag{display:grid;grid-template-columns:22px 1fr;gap:6px;padding:7px 0;border-top:1px solid var(--line)}
.sev{font-weight:700;text-align:center;border-radius:4px;font-size:12px;height:20px;line-height:20px;color:#fff}
.s1{background:#9aa0aa}.s2{background:#c98a1a}.s3{background:#d4572b}.s4{background:var(--red)}
code{font:12px ui-monospace,Menlo,monospace;background:#f1f3f6;padding:1px 4px;border-radius:4px;word-break:break-all}
.link{font-size:13px;padding:5px 0;border-top:1px solid var(--line)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font-size:13.5px}.kv span:nth-child(odd){color:var(--mute)}
.empty{color:var(--mute);text-align:center;padding:80px 20px}.override{color:var(--violet);font-size:13.5px;margin-top:8px}
</style></head><body>
<header><h1>AI Phishing Checker</h1><p>Paste a suspicious email (with or without headers). The checker combines red-flag rules, a machine-learning model, a prompt-injection detector and an LLM.</p></header>
<main>
<section class="card">
  <textarea id="email" placeholder="From: PayPal Security &lt;no-reply@paypa1.com&gt;&#10;Subject: Your account has been locked&#10;&#10;Dear customer, ..."></textarea>
  <div class="row">
    <button class="go" id="go">Check email</button>
    <select id="mode"><option value="full">Full checker</option><option value="rules">Red flags only</option><option value="ml">ML model only</option><option value="llm">LLM only</option></select>
    <span class="small" id="status"></span>
  </div>
  <div class="row small">Try an example: {{EXAMPLES}}</div>
</section>
<section class="card" id="out"><div class="empty">Results appear here.</div></section>
</main>
<script>
const $=s=>document.querySelector(s), esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
fetch('/api/status').then(r=>r.json()).then(s=>{$('#status').textContent=`ML model: ${s.model?'loaded':'missing'} · LLM: ${s.llm?s.llm_model:'off (no API key)'}`;});
document.querySelectorAll('.ex').forEach(b=>b.onclick=async()=>{const r=await fetch('/api/example/'+encodeURIComponent(b.dataset.n));$('#email').value=(await r.json()).raw;});
$('#go').onclick=async()=>{
  const btn=$('#go');btn.disabled=true;btn.textContent='Checking…';
  try{const r=await fetch('/api/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:$('#email').value,mode:$('#mode').value})});
      const d=await r.json(); render(d.error&&!d.verdict?{verdict:'error',summary:d.error,probability:0,reasons:[]}:d);}
  catch(e){render({verdict:'error',summary:String(e),probability:0,reasons:[]});}
  btn.disabled=false;btn.textContent='Check email';};
function render(d){
  const pct=Math.round((d.probability||0)*100), col={phishing:'var(--red)',suspicious:'var(--amber)',legitimate:'var(--green)'}[d.verdict]||'#777';
  let h=`<div class="verdict"><span class="badge ${d.verdict}">${esc(d.verdict)}</span><div><b>${pct}%</b> phishing risk<div class="small">${esc(d.engine||'')}</div></div></div>
  <div class="bar"><i style="width:${pct}%;background:${col}"></i></div><p>${esc(d.summary)}</p>`;
  (d.overrides||[]).forEach(o=>h+=`<div class="override">⚠ ${esc(o)}</div>`);
  if(d.injection&&d.injection.detected){h+=`<div class="inj"><b>Prompt injection detected</b><ul>`+d.injection.findings.map(f=>`<li>${esc(f.message)}${f.hidden?' <i>(hidden from reader)</i>':''}<br><code>${esc(f.evidence)}</code></li>`).join('')+`</ul></div>`;}
  if(d.reasons&&d.reasons.length){h+=`<h3>Why</h3><ul>`+d.reasons.map(r=>`<li>${esc(r)}</li>`).join('')+`</ul>`;}
  if(d.advice)h+=`<h3>What to do</h3><p>${esc(d.advice)}</p>`;
  if(d.red_flags&&d.red_flags.length){h+=`<h3>Red flags (${d.red_flags.length})</h3>`+d.red_flags.map(f=>`<div class="flag"><span class="sev s${f.severity}">${f.severity}</span><div>${esc(f.message)}${f.evidence?`<br><code>${esc(f.evidence.slice(0,200))}</code>`:''}</div></div>`).join('');}
  h+=`<h3>Scores</h3><div class="kv"><span>Rule score</span><span>${d.rule_score??'–'}</span><span>ML score</span><span>${d.ml_score??'–'}${d.ml_terms&&d.ml_terms.length?' · '+d.ml_terms.map(t=>esc(t[0])).join(', '):''}</span><span>LLM</span><span>${d.llm?(d.llm.ok?esc(d.llm.verdict)+' ('+d.llm.probability+')':esc(d.llm.error)):'not used'}</span></div>`;
  const p=d.parsed; if(p&&p.links&&p.links.length){h+=`<h3>Links: shown → actual</h3>`+p.links.map(l=>`<div class="link">${esc(l.text.slice(0,80))} → <code>${esc(l.href.slice(0,160))}</code></div>`).join('');}
  $('#out').innerHTML=h;}
</script></body></html>"""

if __name__ == "__main__":
    import os
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
