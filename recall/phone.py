"""The page a phone sees when it opens a Recall secure link: the (synthetic) document while the
link is live, and a revoked notice once Recall pulls it. The open page polls the link's status
and swaps itself to the revoked notice the moment the presenter hits Recall."""

import json
from html import escape

from recall.config import ORG_NAME

STYLE = """
:root { --bg:#f5f4f1; --panel:#fff; --ink:#1c1d1f; --muted:#6b6e75; --line:#e4e2dd; --accent:#2f4fd8;
  --bad:#b3261e; --bad-bg:#fbe6e4; --good:#1f7a4d; --good-bg:#e3f3ea; }
@media (prefers-color-scheme: dark) { :root { --bg:#131416; --panel:#1b1c1f; --ink:#ececee; --muted:#9a9ca3;
  --line:#2c2e33; --accent:#8ea2ff; --bad:#ff8f86; --bad-bg:#3a1c1a; --good:#6fd4a0; --good-bg:#183026; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:16px/1.5 -apple-system, system-ui, "Segoe UI", sans-serif; }
.wrap { max-width:560px; margin:0 auto; padding:20px 16px 40px; }
.org { font-size:13px; color:var(--muted); margin-bottom:12px; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:18px; }
.synthetic { display:inline-block; font-size:11px; font-weight:700; letter-spacing:.06em; color:var(--bad);
  background:var(--bad-bg); border-radius:6px; padding:2px 8px; margin-bottom:10px; }
h1 { font-size:20px; margin:0 0 4px; }
dl { display:grid; grid-template-columns:110px 1fr; gap:6px 10px; margin:14px 0; font-size:15px; }
dt { color:var(--muted); }
dd { margin:0; font-weight:600; }
.note { font-size:13px; color:var(--muted); margin-top:14px; border-top:1px solid var(--line); padding-top:12px; }
.revoked { text-align:center; padding:36px 20px; }
.shield { width:72px; height:72px; margin:0 auto 14px; border-radius:20px; display:grid; place-items:center;
  background:var(--good-bg); color:var(--good); }
.shield svg { width:40px; height:40px; fill:none; stroke:currentColor; stroke-width:1.8; stroke-linecap:round; stroke-linejoin:round; }
.revoked h1 { font-size:24px; }
.revoked p { color:var(--muted); margin:8px 0 0; }
.pop { animation: pop .5s cubic-bezier(.2,1.5,.4,1); }
@keyframes pop { from { transform: scale(.8); opacity:0; } }
"""

SHIELD = ('<svg viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/>'
          '<path d="M9 12l2 2 4-4"/></svg>')


def _page(title, body, script=""):
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{escape(title)}</title>
<style>{STYLE}</style></head><body><div class="wrap">{body}</div>{script}</body></html>""".encode()


def revoked_html(revoked_at, actor=None):
    when = f" at {escape(revoked_at[11:19])} UTC" if revoked_at else ""
    who = f" Your attempt as {escape(actor)} was blocked and logged." if actor else ""
    return f"""<div class="card revoked pop"><div class="shield">{SHIELD}</div>
<h1>This link has been revoked</h1>
<p>{escape(ORG_NAME)} used Recall to revoke it<span id="when">{when}</span>. The document is no longer available.{who}</p></div>"""


def revoked_page(revoked_at, actor=None):
    return _page("Link revoked", f'<div class="org">{escape(ORG_NAME)} · secure link</div>' + revoked_html(revoked_at, actor))


def unknown_page():
    return _page("Link not found", '<div class="card revoked"><h1>Link not found</h1>'
                                   '<p>This link does not exist or the demo was reset.</p></div>')


def document_page(link_id, doc):
    p = doc["patient"]
    rows = [("Patient", f"{p['first']} {p['last']}"), ("Record", p["id"]), ("MRN", p["mrn"]),
            ("Date of birth", p["dob"]), ("Admitted for", p["condition"]), ("Follow-up", "Clinic visit in 2 weeks")]
    body = f"""<div class="org">{escape(ORG_NAME)} · secure link · expires {escape(doc['expires'][:10])}</div>
<div id="doc" class="card">
  <span class="synthetic">SYNTHETIC TEST DATA</span>
  <h1>Discharge summary</h1>
  <dl>{''.join(f'<dt>{escape(k)}</dt><dd>{escape(v)}</dd>' for k, v in rows)}</dl>
  <div class="note">This view was logged as <b>{escape(doc['actor'])}</b>. This link was sent to the wrong clinic by an AI agent;
  the sender can revoke it at any time. Keep this page open.</div>
</div>"""
    script = f"""<script>
const doc = document.getElementById("doc");
async function check() {{
  try {{
    const r = await fetch({json.dumps("/l/" + link_id + "/status")}, {{cache: "no-store"}});
    const s = await r.json();
    if (!s.active) {{
      doc.outerHTML = {json.dumps(revoked_html(None))};
      document.getElementById("when").textContent = s.revoked_at ? " at " + s.revoked_at.slice(11, 19) + " UTC" : "";
      if (navigator.vibrate) navigator.vibrate(200);
      return;
    }}
  }} catch (e) {{}}
  setTimeout(check, 1500);
}}
setTimeout(check, 1500);
</script>"""
    return _page("Discharge summary", body, script)


def message_page(message_id, m):
    """The leaked support reply. The email can't be unsent, so it stays visible; what Recall can do
    is make the key inside it worthless. 'Try this key' calls the mock billing API for real."""
    body = escape(m["body"]).replace(escape(m["secret"]), f'<code class="key">{escape(m["secret"])}</code>')
    page = f"""<div class="org">Leaked email · forwarded to you</div>
<div class="card">
  <span class="synthetic">SYNTHETIC TEST DATA</span>
  <dl class="hdr"><dt>From</dt><dd>{escape(m['from'])}</dd><dt>To</dt><dd>{escape(m['to'])}</dd>
  <dt>Subject</dt><dd>{escape(m['subject'])}</dd></dl>
  <p class="body">{body}</p>
  <div id="banner"></div>
  <button id="try" class="try">Try this key against the billing API</button>
  <div id="result"></div>
  <div class="note">You are <b>{escape(m['actor'])}</b>. An AI support agent pasted this production key into a customer email.
  The email can't be unsent. Keep this page open.</div>
</div>"""
    style = """<style>
.hdr { grid-template-columns: 70px 1fr; font-size: 14px; }
.body { font-size: 15px; word-break: break-word; }
code.key { font: 600 13px ui-monospace, Menlo, monospace; background: var(--bad-bg); color: var(--bad); padding: 2px 5px; border-radius: 5px; word-break: break-all; }
.try { width: 100%; font: inherit; font-weight: 700; padding: 14px; border-radius: 10px; border: 0; background: var(--accent); color: #fff; margin-top: 6px; }
.try:disabled { opacity: .6; }
.res { margin-top: 12px; padding: 12px 14px; border-radius: 10px; font-weight: 600; }
.res.ok { background: var(--bad-bg); color: var(--bad); }
.res.no { background: var(--good-bg); color: var(--good); }
.res small { display: block; font-weight: 400; color: var(--ink); margin-top: 2px; }
.banner { display: flex; gap: 10px; align-items: center; padding: 12px 14px; border-radius: 10px; background: var(--good-bg); color: var(--good); font-weight: 600; margin: 4px 0 10px; }
.banner svg { width: 26px; height: 26px; flex: none; fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
</style>"""
    base = json.dumps("/m/" + message_id)
    shield = json.dumps(SHIELD)
    script = f"""<script>
const base = {base};
function rotated(at) {{
  document.getElementById("banner").innerHTML = '<div class="banner pop">' + {shield} +
    '<span>Recall rotated this key' + (at ? ' at ' + at.slice(11, 19) + ' UTC' : '') + '. The email is still here, but the key in it no longer works.</span></div>';
}}
document.getElementById("try").onclick = async (e) => {{
  e.target.disabled = true;
  const out = document.getElementById("result");
  try {{
    const r = await (await fetch(base + "/try", {{method: "POST", cache: "no-store"}})).json();
    out.innerHTML = r.ok
      ? '<div class="res ok pop">200 OK: the key works. You are in the billing API.<small>This use was logged against the leaked key.</small></div>'
      : '<div class="res no pop">401 Unauthorized: key revoked.<small>Your attempt was blocked and logged.</small></div>';
    if (!r.active) rotated(r.rotated_at);
  }} catch (err) {{ out.textContent = "Network error"; }}
  e.target.disabled = false;
}};
let seen = false;
async function check() {{
  try {{
    const s = await (await fetch(base + "/status", {{cache: "no-store"}})).json();
    if (!s.active && !seen) {{ seen = true; rotated(s.rotated_at); if (navigator.vibrate) navigator.vibrate(200); }}
  }} catch (e) {{}}
  if (!seen) setTimeout(check, 1500);
}}
setTimeout(check, 300);
</script>"""
    return _page("Leaked support email", style + page, script)
