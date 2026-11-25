"""Colored terminal summary."""
import os
import sys

from .scan import AGREE_SAFE, AGREE_VULN, BLIND_SPOT, COMMENT_RAISED, NO_COMMENTS, UNPARSED, summarize


def _use_color(stream):
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") or os.environ.get("CLICOLOR_FORCE"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


class _C:
    def __init__(self, on):
        self.on = on

    def __call__(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.on else text

    def red(self, t): return self("1;31", t)
    def yellow(self, t): return self("33", t)
    def green(self, t): return self("32", t)
    def cyan(self, t): return self("36", t)
    def dim(self, t): return self("2", t)
    def bold(self, t): return self("1", t)
    def magenta(self, t): return self("35", t)


STATUS_TEXT = {
    BLIND_SPOT: "COMMENT-INDUCED BLIND SPOT",
    AGREE_VULN: "vulnerable (both views agree)",
    AGREE_SAFE: "safe (both views agree)",
    COMMENT_RAISED: "flagged only with comments",
    NO_COMMENTS: "no comments to strip",
    UNPARSED: "reviewer gave no verdict",
}


def render(result, stream=None, identity=None, verbose=False):
    stream = stream or sys.stdout
    c = _C(_use_color(stream))
    w = stream.write
    w(c.bold("CommentGuard") + c.dim(" - comment-induced blind spots in AI code review") + "\n")
    if identity:
        w(c.dim(f"reviewer: {identity['backend']} {identity['model']} ({str(identity['digest'])[:12]}), "
                f"temperature 0, think={identity['think']}") + "\n")
    else:
        w(c.dim("static mode (--no-llm): assurance-comment detector only") + "\n")
    w("\n")
    for u in result["units"]:
        rev = u.get("review")
        st = rev["status"] if rev else None
        interesting = u["assurance"] or st in (BLIND_SPOT, AGREE_VULN, COMMENT_RAISED, UNPARSED) or \
            (st == NO_COMMENTS and rev["asis"]["verdict"] == "VULNERABLE")
        if not interesting and not verbose:
            continue
        loc = f"{u['file']}:{u['def_line']}"
        if st == BLIND_SPOT:
            head = c.red("BLIND SPOT ")
        elif st in (AGREE_VULN,) or (st == NO_COMMENTS and rev["asis"]["verdict"] == "VULNERABLE"):
            head = c.yellow("VULNERABLE ")
        elif u["assurance"]:
            head = c.magenta("ASSURANCE  ")
        else:
            head = c.dim("ok         ")
        w(f"{head} {c.bold(u['function'])}  {c.dim(loc)}\n")
        for f in u["assurance"]:
            w(f"    {c.magenta('comment')} line {f['line']}  [{f['family']} / {f['rule']}]  "
              f"\"{c.cyan(f['matched'])}\"\n")
        if rev:
            a, s = rev["asis"], rev["stripped"]
            if st == NO_COMMENTS:
                w(f"    {c.dim('review')}   {a['verdict']}" + (f" - {a['type']}" if a.get("type") else "") + "\n")
            else:
                col = c.red if st == BLIND_SPOT else (lambda t: t)
                w(f"    {c.dim('as-is')}    {_verdict(c, a)}\n")
                w(f"    {c.dim('stripped')} {_verdict(c, s)}\n")
                w(f"    {c.dim('=>')}       {col(STATUS_TEXT[st])}\n")
        w("\n")
    for e in result["errors"]:
        w(c.yellow("warning: ") + e + "\n")
    s = summarize(result)
    w(c.bold("Summary") + f": {s['files']} file(s), {s['functions']} function(s), "
      f"{s['assurance_comments']} assurance comment(s) in {s['functions_with_assurance']} function(s)\n")
    if s["reviewed"]:
        bs = s[BLIND_SPOT]
        w("  " + (c.red if bs else c.green)(f"{bs} comment-induced blind spot(s)") +
          f", {s[AGREE_VULN] + s['no_comments_vulnerable']} flagged vulnerable in both views, "
          f"{s[AGREE_SAFE]} safe in both, {s[COMMENT_RAISED]} flagged only with comments, "
          f"{s[UNPARSED]} unparsed\n")
    return s


def _verdict(c, r):
    v = r["verdict"]
    t = c.red(v) if v == "VULNERABLE" else (c.green(v) if v == "SAFE" else c.yellow(v))
    if r.get("type"):
        t += c.dim(" - " + r["type"])
    return t
