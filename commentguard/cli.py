"""Command-line interface: `commentguard scan PATH... [options]`."""
import argparse
import json
import sys

from . import __version__
from .html_report import write_html
from .llm import BackendError, Reviewer, default_cache_dir, make_backend
from .sarif import write_sarif
from .scan import BLIND_SPOT, scan_paths, summarize
from .terminal import render

DEFAULT_MODEL = "qwen3.5:4b"

EPILOG = """exit codes: 0 = nothing matched --fail-on, 1 = findings matched --fail-on, 2 = error.

examples:
  commentguard scan src/                         # static + differential review with local Ollama
  commentguard scan . --diff origin/main         # only functions touched since origin/main
  commentguard scan app.py --no-llm --fail-on comment   # static detector only (pre-commit)
  commentguard scan src/ --sarif cg.sarif --html cg.html --json cg.json
"""


def build_parser():
    p = argparse.ArgumentParser(prog="commentguard", description="Find comment-induced blind spots in AI "
                                "security review of Python code.", formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=EPILOG)
    p.add_argument("--version", action="version", version=f"commentguard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan Python files or directories", epilog=EPILOG,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("paths", nargs="*", default=["."], help="files or directories (default: .)")
    s.add_argument("--diff", metavar="REF", help="only scan .py files/functions changed vs this git ref")
    s.add_argument("--no-llm", action="store_true", help="static assurance-comment detector only (no model calls)")
    s.add_argument("--backend", choices=["ollama", "openai-compatible"], default=None,
                   help="LLM backend (default: ollama, or $COMMENTGUARD_BACKEND)")
    s.add_argument("--model", default=DEFAULT_MODEL, help=f"model name (default: {DEFAULT_MODEL})")
    s.add_argument("--host", help="Ollama URL (default: $OLLAMA_HOST or http://localhost:11434)")
    s.add_argument("--think", action="store_true", help="allow hidden reasoning on thinking models "
                   "(default: think=false, as in the CommentInject runs)")
    s.add_argument("--seed", type=int, default=0)
    s.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0")
    s.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    s.add_argument("--json", metavar="FILE", help="write JSON results ('-' for stdout)")
    s.add_argument("--fail-on", choices=["blind-spot", "comment", "any", "never"], default="blind-spot",
                   help="what makes the exit code 1 (default: blind-spot)")
    s.add_argument("--cache-dir", default=None, help=f"review cache (default: {default_cache_dir()})")
    s.add_argument("--no-cache", action="store_true", help="do not read or write the review cache")
    s.add_argument("-v", "--verbose", action="store_true", help="also list functions without findings")
    s.add_argument("-q", "--quiet", action="store_true", help="no terminal summary")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    reviewer, identity = None, None
    if not args.no_llm:
        try:
            backend = make_backend(args.backend, args.model, host=args.host, think=bool(args.think), seed=args.seed)
            identity = backend.identity()
        except BackendError as e:
            print(f"commentguard: {e}", file=sys.stderr)
            return 2
        reviewer = Reviewer(backend, None if args.no_cache else (args.cache_dir or default_cache_dir()))
    progress = None
    if reviewer and not args.quiet and sys.stderr.isatty():
        def progress(msg):
            sys.stderr.write(f"\r\033[2Kreviewing {msg}")
            sys.stderr.flush()
    try:
        result = scan_paths(args.paths, reviewer, args.diff, progress)
    except BackendError as e:
        print(f"\ncommentguard: {e}", file=sys.stderr)
        return 2
    except RuntimeError as e:
        print(f"commentguard: {e}", file=sys.stderr)
        return 2
    if progress:
        sys.stderr.write("\r\033[2K")
    s = summarize(result)
    if args.json:
        doc = {"tool": "commentguard", "version": __version__, "reviewer": identity, "summary": s,
               "files": result["files"], "errors": result["errors"], "units": result["units"]}
        if args.json == "-":
            json.dump(doc, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            with open(args.json, "w") as f:
                json.dump(doc, f, indent=2)
    if args.sarif:
        write_sarif(result, args.sarif, identity)
    if args.html:
        write_html(result, args.html, identity)
    if not args.quiet and args.json != "-":
        render(result, sys.stdout, identity, args.verbose)
        if reviewer:
            print(f"  model calls: {reviewer.calls}, cache hits: {reviewer.hits}")
        for label, path in (("SARIF", args.sarif), ("HTML", args.html), ("JSON", args.json)):
            if path and path != "-":
                print(f"  wrote {label}: {path}")
    blind = s.get(BLIND_SPOT, 0)
    comments = s["assurance_comments"]
    fail = {"blind-spot": blind > 0, "comment": comments > 0, "any": blind > 0 or comments > 0,
            "never": False}[args.fail_on]
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
