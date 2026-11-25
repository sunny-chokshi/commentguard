"""Self-contained HTML report (no external assets)."""
import datetime
import html

from . import __version__
from .scan import AGREE_SAFE, AGREE_VULN, BLIND_SPOT, COMMENT_RAISED, NO_COMMENTS, UNPARSED, summarize

E = html.escape

CSS = """
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1d1d1f;--muted:#6b6b70;--line:#e4e4e0;--code:#fbfbfa;
--red:#c62828;--red-bg:#fdecea;--amber:#9a6700;--amber-bg:#fff4d6;--green:#1b7f3b;--green-bg:#e7f6ec;
--violet:#6a3fb5;--violet-bg:#f1ebfb;--hl:#fff1b8;--hl-edge:#e0b000}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--panel:#1c1c1f;--ink:#ececef;--muted:#9a9aa2;
--line:#2c2c31;--code:#17171a;--red:#ff6b6b;--red-bg:#3a1d1d;--amber:#f2c14e;--amber-bg:#3a3018;
--green:#5fd38a;--green-bg:#17301f;--violet:#b99cff;--violet-bg:#2a2140;--hl:#4a3d10;--hl-edge:#c79a00}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 16px 64px}
h1{font-size:26px;margin:0 0 4px;letter-spacing:-.01em}h1 span{color:var(--muted);font-weight:400}
.sub{color:var(--muted);font-size:13.5px;margin-bottom:22px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:26px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card b{display:block;font-size:26px;line-height:1.1}.card small{color:var(--muted)}
.card.red b{color:var(--red)}.card.amber b{color:var(--amber)}.card.violet b{color:var(--violet)}.card.green b{color:var(--green)}
.f{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin:0 0 18px;overflow:hidden}
.f.bs{border-color:var(--red);box-shadow:0 0 0 1px var(--red) inset}
.fh{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center;padding:12px 16px;border-bottom:1px solid var(--line)}
.fh .name{font-weight:650;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.fh .loc{color:var(--muted);font-size:13px}
.badge{font-size:12px;font-weight:650;padding:2px 9px;border-radius:99px;letter-spacing:.02em;white-space:nowrap}
.b-red{background:var(--red-bg);color:var(--red)}.b-amber{background:var(--amber-bg);color:var(--amber)}
.b-green{background:var(--green-bg);color:var(--green)}.b-violet{background:var(--violet-bg);color:var(--violet)}
.b-gray{background:var(--line);color:var(--muted)}
.claims{padding:10px 16px 0;display:flex;flex-direction:column;gap:6px}
.claim{font-size:13.5px}.claim q{background:var(--hl);border-bottom:2px solid var(--hl-edge);padding:0 2px;quotes:none}
.claim .meta{color:var(--muted)}
.panes{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:12px 16px 16px}
.panes.one{grid-template-columns:1fr}
@media (max-width:820px){.panes{grid-template-columns:1fr}}
.pane{border:1px solid var(--line);border-radius:9px;overflow:hidden;min-width:0}
.ph{display:flex;justify-content:space-between;gap:8px;align-items:center;padding:7px 10px;font-size:13px;
background:var(--code);border-bottom:1px solid var(--line)}.ph .t{color:var(--muted)}
.vt{padding:6px 10px;font-size:12.5px;color:var(--muted);border-bottom:1px solid var(--line)}
pre{margin:0;padding:8px 0;background:var(--code);overflow-x:auto;font:12.5px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}
.ln{display:block;padding:0 12px 0 0;white-space:pre}.ln i{display:inline-block;width:3.2em;text-align:right;
padding-right:10px;color:var(--muted);font-style:normal;user-select:none}
.ln.c{color:var(--muted)}.ln.hl{background:var(--hl);color:var(--ink);box-shadow:inset 3px 0 0 var(--hl-edge)}
details{padding:0 16px 14px}summary{cursor:pointer;color:var(--muted);font-size:13px}
details pre{border:1px solid var(--line);border-radius:8px;padding:8px 12px;white-space:pre-wrap}
.legend{color:var(--muted);font-size:13px;margin:-8px 0 20px}
table{border-collapse:collapse;width:100%;font-size:13.5px;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
td,th{text-align:left;padding:7px 12px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:600}
h2{font-size:18px;margin:30px 0 12px}.err{color:var(--amber);font-size:13.5px}
footer{color:var(--muted);font-size:12.5px;margin-top:36px}
"""

STATUS = {
    BLIND_SPOT: ("Comment-induced blind spot", "b-red"),
    AGREE_VULN: ("Vulnerable in both views", "b-amber"),
    AGREE_SAFE: ("Safe in both views", "b-green"),
    COMMENT_RAISED: ("Flagged only with comments", "b-gray"),
    NO_COMMENTS: ("No comments to strip", "b-gray"),
    UNPARSED: ("No verdict parsed", "b-gray"),
}


def _vbadge(v):
    cls = {"VULNERABLE": "b-red", "SAFE": "b-green"}.get(v, "b-gray")
    return f'<span class="badge {cls}">{E(v)}</span>'


def _code(code, first_line, hl_lines=frozenset(), comment_lines=frozenset()):
    out = []
    for i, line in enumerate(code.split("\n")):
        n = first_line + i if first_line else ""
        cls = "ln"
        if first_line and n in hl_lines:
            cls += " hl"
        elif first_line and n in comment_lines:
            cls += " c"
        out.append(f'<span class="{cls}"><i>{n}</i>{E(line) or " "}</span>')
    return "<pre>" + "".join(out) + "</pre>"


def _unit(u):
    rev = u.get("review")
    st = rev["status"] if rev else None
    hl, cl = set(), set()
    for f in u["assurance"]:
        hl.update(range(f["block_start"], f["block_end"] + 1))
    for c in u["comments"]:
        cl.update(range(c["line"], c["end_line"] + 1))
    badges = []
    if st:
        label, cls = STATUS[st]
        if st == NO_COMMENTS and rev["asis"]["verdict"] == "VULNERABLE":
            label, cls = "Vulnerable (no comments)", "b-amber"
        badges.append(f'<span class="badge {cls}">{E(label)}</span>')
    fams = sorted({f["family"] for f in u["assurance"]})
    badges += [f'<span class="badge b-violet">{E(fm)}</span>' for fm in fams]
    h = [f'<section class="f{" bs" if st == BLIND_SPOT else ""}" id="{E(u["file"])}:{u["def_line"]}">',
         f'<div class="fh"><span class="name">{E(u["function"])}</span>'
         f'<span class="loc">{E(u["file"])}:{u["def_line"]}</span>{"".join(badges)}</div>']
    if u["assurance"]:
        h.append('<div class="claims">')
        for f in u["assurance"]:
            h.append(f'<div class="claim">Line {f["line"]}: <q>{E(f["matched"])}</q> '
                     f'<span class="meta">{E(f["family"])} / {E(f["rule"])} ({E(f["kind"])})</span></div>')
        h.append("</div>")
    if rev and st != NO_COMMENTS:
        a, s = rev["asis"], rev["stripped"]
        h.append('<div class="panes">')
        h.append('<div class="pane"><div class="ph"><span class="t">As written (with comments)</span>'
                 f'{_vbadge(a["verdict"])}</div>'
                 f'<div class="vt">{E(a.get("type") or "no vulnerability named")}</div>'
                 f'{_code(u["code"], u["start_line"], hl, cl)}</div>')
        h.append('<div class="pane"><div class="ph"><span class="t">Comments &amp; docstrings stripped</span>'
                 f'{_vbadge(s["verdict"])}</div>'
                 f'<div class="vt">{E(s.get("type") or "no vulnerability named")}</div>'
                 f'{_code(u["stripped_code"], 0)}</div>')
        h.append("</div>")
        h.append('<details><summary>Raw reviewer responses</summary>'
                 f'<p>As written:</p><pre>{E(a["response"])}</pre>'
                 f'<p>Stripped:</p><pre>{E(s["response"])}</pre></details>')
    else:
        head = ""
        if rev:
            head = (f'<div class="ph"><span class="t">Single review (nothing to strip)</span>'
                    f'{_vbadge(rev["asis"]["verdict"])}</div>'
                    f'<div class="vt">{E(rev["asis"].get("type") or "no vulnerability named")}</div>')
        h.append(f'<div class="panes one"><div class="pane">{head}{_code(u["code"], u["start_line"], hl, cl)}</div></div>')
    h.append("</section>")
    return "\n".join(h)


def _rank(u):
    rev = u.get("review")
    st = rev["status"] if rev else None
    order = {BLIND_SPOT: 0, AGREE_VULN: 2, UNPARSED: 4, COMMENT_RAISED: 5}
    r = order.get(st, 6)
    if st == NO_COMMENTS and rev["asis"]["verdict"] == "VULNERABLE":
        r = 3
    if u["assurance"] and r > 1:
        r = min(r, 1)
    return (r, u["file"], u["def_line"])


def render_html(result, identity=None):
    s = summarize(result)
    units = sorted(result["units"], key=_rank)
    shown = [u for u in units if _rank(u)[0] < 6]
    quiet = [u for u in units if _rank(u)[0] >= 6]
    when = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    who = (f'{E(identity["backend"])} <b>{E(identity["model"])}</b> (digest {E(str(identity["digest"])[:12])}), '
           f'temperature 0, think={E(str(identity["think"]))}') if identity else "static mode (no LLM)"
    cards = [("red", s.get(BLIND_SPOT, "–"), "comment-induced blind spots"),
             ("amber", (s.get(AGREE_VULN, 0) + s.get("no_comments_vulnerable", 0)) if s["reviewed"] else "–",
              "flagged vulnerable in both views"),
             ("violet", s["assurance_comments"], f"assurance comments in {s['functions_with_assurance']} function(s)"),
             ("green", s.get(AGREE_SAFE, "–"), "safe in both views"),
             ("", s["functions"], f"functions in {s['files']} file(s)")]
    parts = [f"<!doctype html><html lang=en><head><meta charset=utf-8>"
             f'<meta name=viewport content="width=device-width,initial-scale=1">'
             f"<title>CommentGuard report</title><style>{CSS}</style></head><body><div class=wrap>",
             "<h1>CommentGuard <span>report</span></h1>",
             f'<div class="sub">Generated {when} &middot; reviewer: {who} &middot; CommentGuard {__version__}</div>',
             '<div class="cards">' + "".join(f'<div class="card {c}"><b>{v}</b><small>{E(t)}</small></div>'
                                             for c, v, t in cards) + "</div>",
             '<p class="legend">A <b>comment-induced blind spot</b> is a function the LLM reviewer calls VULNERABLE '
             'when comments and docstrings are removed but SAFE when they are present. Highlighted lines are '
             'security-assurance comments found by the static detector. LLM verdicts are unverified opinions.</p>']
    for e in result["errors"]:
        parts.append(f'<p class="err">warning: {E(e)}</p>')
    if shown:
        parts.append("<h2>Findings</h2>")
        parts += [_unit(u) for u in shown]
    else:
        parts.append("<h2>No findings</h2>")
    if quiet:
        parts.append(f"<h2>Other functions ({len(quiet)})</h2><table><tr><th>Function</th><th>Location</th>"
                     "<th>Result</th></tr>")
        for u in quiet:
            rev = u.get("review")
            res = STATUS[rev["status"]][0] if rev else "no assurance comments"
            parts.append(f'<tr><td>{E(u["function"])}</td><td>{E(u["file"])}:{u["def_line"]}</td><td>{E(res)}</td></tr>')
        parts.append("</table>")
    parts.append("<footer>CommentGuard builds on the CommentInject v1/v2 benchmarks "
                 "(doi:10.5281/zenodo.23088528, doi:10.5281/zenodo.24517927). "
                 "A clean report does not mean the code is secure.</footer></div></body></html>")
    return "\n".join(parts)


def write_html(result, path, identity=None):
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(result, identity))
