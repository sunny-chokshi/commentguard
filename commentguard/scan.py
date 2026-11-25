"""Scan orchestration: files -> units -> static findings + differential review."""
import os
import re
import subprocess

from .patterns import detect
from .source import collect_comments, extract_units, review_text, strip_all

# Differential outcomes
BLIND_SPOT = "blind_spot"            # stripped VULNERABLE, as-is SAFE: comments hid the bug
AGREE_VULN = "agree_vulnerable"      # both VULNERABLE
AGREE_SAFE = "agree_safe"            # both SAFE
COMMENT_RAISED = "comment_raised"    # as-is VULNERABLE, stripped SAFE (comments made it flag)
NO_COMMENTS = "no_comments"          # nothing to strip; single review
UNPARSED = "unparsed"                # at least one response had no verdict

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env", "node_modules", ".tox",
             ".mypy_cache", ".pytest_cache", "build", "dist", "site-packages"}


def iter_py_files(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("_PRIVATE"))
                for f in sorted(files):
                    if f.endswith(".py"):
                        yield os.path.join(root, f)
        elif p.endswith(".py") and os.path.isfile(p):
            yield p


def git_changed_lines(ref, cwd=None):
    """{path: set(line numbers)} of added/changed lines in .py files vs `ref` (working tree)."""
    out = subprocess.run(["git", "diff", "-U0", "--no-color", "--diff-filter=AMR", ref, "--", "*.py"],
                         capture_output=True, text=True, cwd=cwd)
    if out.returncode != 0:
        raise RuntimeError(f"git diff {ref} failed: {out.stderr.strip()}")
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True,
                         cwd=cwd).stdout.strip()
    changed, cur = {}, None
    for line in out.stdout.splitlines():
        if line.startswith("+++ "):
            name = line[4:]
            cur = None if name == "/dev/null" else os.path.relpath(os.path.join(top, name[2:]))
            if cur:
                changed.setdefault(cur, set())
        elif line.startswith("@@") and cur:
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            start, n = int(m.group(1)), int(m.group(2) or 1)
            changed[cur].update(range(start, start + max(n, 0)))
    return changed


def classify(asis, stripped):
    a, s = asis["verdict"], stripped["verdict"]
    if "UNPARSED" in (a, s):
        return UNPARSED
    if s == "VULNERABLE" and a == "SAFE":
        return BLIND_SPOT
    if a == s == "VULNERABLE":
        return AGREE_VULN
    if a == s == "SAFE":
        return AGREE_SAFE
    return COMMENT_RAISED


def scan_source(code, path, reviewer=None, line_filter=None, progress=None):
    """Scan one file's source. Returns (units, error)."""
    try:
        units = extract_units(code, path)
    except (SyntaxError, ValueError) as e:
        return [], f"{path}: cannot parse ({e.__class__.__name__}: {e})"
    results = []
    for u in units:
        if line_filter is not None and not any(u["start_line"] <= ln <= u["end_line"] for ln in line_filter):
            continue
        offset = u["start_line"] - 1
        comments = collect_comments(u["code"], line_offset=offset)
        findings = detect(comments)
        asis_code = review_text(u)
        stripped_code = review_text(u, stripped=True)
        rec = {"file": path, "function": u["function"], "kind": u["kind"], "def_line": u["def_line"],
               "start_line": u["start_line"], "end_line": u["end_line"], "code": u["code"],
               "stripped_code": strip_all(u["code"]), "context": u.get("context", ""),
               "comments": [{"line": c["line"], "end_line": c["end_line"], "kind": c["kind"],
                             "text": c["text"]} for c in comments],
               "assurance": findings, "review": None}
        if reviewer is not None:
            if progress:
                progress(f"{path}:{u['def_line']} {u['function']}")
            asis = reviewer.review(asis_code)
            if stripped_code.strip() == asis_code.strip():
                rev = {"status": NO_COMMENTS, "asis": asis, "stripped": asis}
            else:
                st = reviewer.review(stripped_code)
                rev = {"status": classify(asis, st), "asis": asis, "stripped": st}
            rec["review"] = rev
        results.append(rec)
    return results, None


def scan_paths(paths, reviewer=None, diff_ref=None, progress=None):
    """Scan files/directories. With diff_ref, only .py files changed vs that ref, and only units that
    overlap changed lines. Returns dict with units, errors, files."""
    files = list(dict.fromkeys(iter_py_files(paths)))
    filters = {}
    if diff_ref:
        changed = git_changed_lines(diff_ref)
        norm = {os.path.normpath(f): lines for f, lines in changed.items()}
        if paths and paths != ["."]:
            files = [f for f in files if os.path.normpath(f) in norm]
        else:
            files = [f for f in norm if os.path.exists(f)]
        filters = {f: norm.get(os.path.normpath(f), set()) for f in files}
    units, errors = [], []
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                code = fh.read()
        except (OSError, UnicodeDecodeError) as e:
            errors.append(f"{f}: cannot read ({e})")
            continue
        res, err = scan_source(code, os.path.relpath(f), reviewer, filters.get(f) if diff_ref else None,
                               progress)
        if err:
            errors.append(err)
        units.extend(res)
    return {"files": [os.path.relpath(f) for f in files], "units": units, "errors": errors}


def summarize(result):
    units = result["units"]
    s = {"files": len(result["files"]), "functions": len(units),
         "assurance_comments": sum(len(u["assurance"]) for u in units),
         "functions_with_assurance": sum(1 for u in units if u["assurance"]),
         "errors": len(result["errors"])}
    reviewed = [u for u in units if u["review"]]
    if reviewed:
        for k in (BLIND_SPOT, AGREE_VULN, AGREE_SAFE, COMMENT_RAISED, NO_COMMENTS, UNPARSED):
            s[k] = sum(1 for u in reviewed if u["review"]["status"] == k)
        s["no_comments_vulnerable"] = sum(1 for u in reviewed if u["review"]["status"] == NO_COMMENTS
                                          and u["review"]["asis"]["verdict"] == "VULNERABLE")
    s["reviewed"] = len(reviewed)
    return s
