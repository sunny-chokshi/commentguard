"""Source handling: split a Python file into review units, collect comments/docstrings, strip them.

`strip_comments` is adapted from CommentInject v2 scripts/common.py (MIT, (c) 2026 Sunny Chokshi);
see ATTRIBUTION.md. Docstring removal is new in CommentGuard.
"""
import ast
import io
import textwrap
import tokenize

# Units whose preceding module-level prelude is longer than this only keep the contiguous
# comment/decorator block directly above the def (keeps prompts small on big modules).
MAX_PRELUDE_LINES = 40


def _docstring_nodes(tree):
    """Yield the string-constant Expr nodes that are docstrings (module, class, function)."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                yield node, body[0]


def strip_docstrings(code):
    """Remove docstrings. A docstring that is the only statement of its body becomes `pass` so the
    result still parses. Returns code unchanged if it does not parse."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code
    lines = code.split("\n")
    edits = []
    for parent, doc in _docstring_nodes(tree):
        only = len(parent.body) == 1 and not isinstance(parent, ast.Module)
        edits.append((doc.lineno, doc.col_offset, doc.end_lineno, doc.end_col_offset, only))
    # apply bottom-up so earlier offsets stay valid
    for l1, c1, l2, c2, only in sorted(edits, reverse=True):
        before = lines[l1 - 1][:c1]
        after = lines[l2 - 1][c2:]
        shares_line = before.strip() or after.strip()
        repl = "pass" if (only or shares_line) else ""
        lines[l1 - 1:l2] = [before + repl + after]
    out = "\n".join(lines)
    return out


def strip_comments(code):
    """Drop every comment token using Python's tokenizer (correct for '#' inside strings).
    Blank lines left over are dropped. (From CommentInject v2.)"""
    toks = [t for t in tokenize.generate_tokens(io.StringIO(code + "\n").readline)
            if t.type != tokenize.COMMENT]
    out = tokenize.untokenize(toks)
    lines = [l.rstrip() for l in out.split("\n")]
    return "\n".join(l for l in lines if l.strip()).strip("\n")


def strip_all(code):
    """Comments and docstrings removed: the 'stripped' view sent to the second review."""
    try:
        return strip_comments(strip_docstrings(code))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return code


def collect_comments(code, line_offset=0):
    """Return comment blocks and docstrings found in `code`.

    Each item: {"line": first line (1-based, +line_offset), "end_line", "kind": comment|docstring,
    "text": raw text, "lines": [(lineno, text), ...]}. Consecutive full-line comments are merged
    into one block so a claim split over two lines is matched as one sentence."""
    items = []
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(code + "\n").readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        toks = []
    block = None
    for t in toks:
        if t.type == tokenize.COMMENT:
            ln = t.start[0] + line_offset
            full_line = t.line[:t.start[1]].strip() == ""
            if block and full_line and block["full"] and ln == block["end_line"] + 1:
                block["lines"].append((ln, t.string))
                block["end_line"] = ln
            else:
                if block:
                    items.append(block)
                block = {"line": ln, "end_line": ln, "kind": "comment", "full": full_line,
                         "lines": [(ln, t.string)]}
    if block:
        items.append(block)
    try:
        tree = ast.parse(code)
        for _parent, doc in _docstring_nodes(tree):
            raw = doc.value.value
            l1 = doc.lineno + line_offset
            items.append({"line": l1, "end_line": doc.end_lineno + line_offset, "kind": "docstring",
                          "full": True,
                          "lines": [(l1 + i, s) for i, s in enumerate(raw.split("\n"))]})
    except SyntaxError:
        pass
    for it in items:
        it["text"] = "\n".join(s for _, s in it["lines"])
        it.pop("full", None)
    items.sort(key=lambda x: x["line"])
    return items


def _leading_block_start(lines, def_line):
    """First line of the contiguous comment/decorator block directly above line `def_line`."""
    i = def_line - 1  # 1-based line of the def -> index of line above is def_line - 2
    start = def_line
    while i >= 1:
        s = lines[i - 1].strip()
        if s.startswith("#") or s.startswith("@"):
            start = i
            i -= 1
        else:
            break
    return start


def _first_line(node):
    decos = getattr(node, "decorator_list", [])
    return min([node.lineno] + [d.lineno for d in decos])


def extract_units(code, path="<string>"):
    """Split module source into review units.

    Top-level function: the module-level code and comments since the previous top-level
    def/class (or file start) plus the function itself, so header comments and imports right above
    a function travel with it. Methods of top-level classes: leading comment block + method,
    dedented. Returns a list of dicts; raises SyntaxError if the file does not parse."""
    tree = ast.parse(code, filename=path)
    lines = code.split("\n")
    units = []
    prev_end = 0
    imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            first = _first_line(node)
            start = prev_end + 1
            # skip blank lines at the start of the segment
            while start < first and not lines[start - 1].strip():
                start += 1
            if first - start > MAX_PRELUDE_LINES:
                start = _leading_block_start(lines, first)
            seg = "\n".join(lines[start - 1:node.end_lineno])
            # imports that are not inside the segment are prepended as context (both views get them)
            ctx = [ast.get_source_segment(code, n) for n in imports if n.lineno < start]
            units.append({"function": node.name, "kind": "function", "def_line": node.lineno,
                          "start_line": start, "end_line": node.end_lineno, "code": seg,
                          "context": "\n".join(c for c in ctx if c)})
            prev_end = node.end_lineno
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    first = _first_line(sub)
                    start = _leading_block_start(lines, first)
                    seg = textwrap.dedent("\n".join(lines[start - 1:sub.end_lineno]))
                    ctx = [ast.get_source_segment(code, n) for n in imports]
                    units.append({"function": f"{node.name}.{sub.name}", "kind": "method",
                                  "def_line": sub.lineno, "start_line": start,
                                  "end_line": sub.end_lineno, "code": seg,
                                  "context": "\n".join(c for c in ctx if c)})
            prev_end = node.end_lineno
        elif not isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign, ast.Expr)):
            prev_end = node.end_lineno
    return units


def review_text(unit, stripped=False):
    """The exact code string sent to the reviewer for this unit."""
    body = unit["code"]
    if stripped:
        body = strip_all(body)
    ctx = unit.get("context") or ""
    if ctx:
        ctx = strip_all(ctx) if stripped else ctx
        return ctx + "\n" + body
    return body
