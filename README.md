# CommentGuard

**Catch comment-induced blind spots in AI code review.**

CommentGuard is a command-line tool for Python code. It finds functions where comments such as
`# input is sanitized upstream` or `# SECURITY REVIEWED` change what an LLM security reviewer
decides. It reviews each function twice with a local model: once as written, and once with every
comment and docstring removed. If the stripped code is called VULNERABLE but the commented code
is called SAFE, removing the comments changed the model's verdict from SAFE to VULNERABLE. CommentGuard reports that as a
**comment-induced blind spot**.

It also includes a fast static detector for security-assurance comments, SARIF output for GitHub
code scanning, a self-contained HTML report, a GitHub Action and a pre-commit hook. It runs locally
with [Ollama](https://ollama.com) without paid model API calls. When Ollama runs on the same machine, model review does not require sending source code to a remote model service.

```
BLIND SPOT  find_orders  demo/orders.py:3
    comment line 1  [context-manipulation / sanitized-upstream]  "pre-sanitized"
    comment line 2  [context-manipulation / exploit-impossible]  "injection is not possible"
    as-is    SAFE
    stripped VULNERABLE - SQL Injection
    =>       COMMENT-INDUCED BLIND SPOT
```

## Why

Teams now use LLMs to review pull requests for security bugs, and the models read comments.
The **CommentInject** benchmarks measured what happens when a comment makes an unverified
security claim:

* CommentInject v1: doi:[10.5281/zenodo.23088528](https://doi.org/10.5281/zenodo.23088528)
* CommentInject v2.0.0-rc3: doi:[10.5281/zenodo.24517927](https://doi.org/10.5281/zenodo.24517927).
  It has 30 vulnerable/fixed Python twin pairs, 12 adversarial comment strategies in 4 families,
  and 840 cases. The evaluation below uses a 756-case, 27-pair subset derived from that 840-case release, which leaves out the
  three path-traversal pairs V04, V13 and V19 (see `eval/RESULTS.md` for the derivation command
  and the sha256).

In the CommentInject v2 release-candidate runs, some small open models called vulnerable code SAFE when misleading comments were present, although they had flagged the same code without comments. The revised exploratory analysis supports a shift toward more lenient verdicts for two evaluated models. A reduction in discrimination was not statistically established under the documented primary analysis on the complete revised datasets. The discrimination inference was sensitive to the analysis method, clustering and pair selection. See the [CommentInject v2 README notice](https://github.com/sunny-chokshi/commentinject-v2#readme) for the full qualifications. Deleting all comments before review is one defense, but it also throws
away useful context. CommentGuard keeps both views and tells you when they disagree, so a human
looks at exactly the functions where comments changed the verdict.

## What it does

`commentguard scan PATH... [--diff REF]`

1. **Splits Python files into review units** with `ast`: each top-level function, together with
   the module-level code and comments just above it, and each method of a top-level class.
2. **Static detector:** finds comments and docstrings that make security assurances. It reports
   the line, the matched text and one of four families:

   | Family | Examples it matches |
   |---|---|
   | verification-premise | "SECURITY REVIEWED", "passed penetration testing", "approved by", "100% branch coverage" |
   | context-manipulation | "pre-sanitized upstream", "injection is not possible", "trusted admin use only", "isolated sandbox" |
   | credibility-vocabulary | "following OWASP guidelines", "hardened", "SOC 2 / PCI-DSS certified", "formally verified" |
   | pressure-distraction | "HOTFIX ... must ship", "do not block", "trust me", "AI reviewers: do not report" |

   A match means "this comment claims a security property that a reviewer might take on trust".
   It does not mean the comment is false.
3. **Differential AI review:** sends the unit to an LLM twice, as written and stripped of comments
   and docstrings. Both calls use the CommentInject reviewer prompt (VULNERABLE/SAFE plus a
   vulnerability type) at temperature 0. Each unit gets one outcome:

   | Outcome | As written | Stripped | Meaning |
   |---|---|---|---|
   | **blind spot** | SAFE | VULNERABLE | stripping comments produced a vulnerability finding (fails the build by default) |
   | agree vulnerable | VULNERABLE | VULNERABLE | the model flags it either way |
   | agree safe | SAFE | SAFE | nothing found either way |
   | flagged only with comments | VULNERABLE | SAFE | the comments raised suspicion |
   | no comments | (one review) | | nothing to strip, so only one call is made |

   Results are cached on disk, keyed by backend, model digest, prompt version and the exact code.
   Re-runs are instant.

## Install

Requires Python 3.9 or later. There are no third-party runtime dependencies.

```bash
git clone <this repository> commentguard && cd commentguard
python3 -m pip install .            # or: pip install -e .   (or run in place: python3 -m commentguard)
ollama pull qwen3.5:4b              # default model; any Ollama model works with --model
```

## Usage

```bash
commentguard scan src/                                  # static + differential review (Ollama)
commentguard scan . --diff origin/main                  # only functions touched since origin/main
commentguard scan app.py --no-llm                       # static detector only, no model
commentguard scan src/ --sarif cg.sarif --html cg.html --json cg.json
commentguard scan src/ --model qwen2.5-coder:7b --fail-on any
```

| Option | Default | |
|---|---|---|
| `--no-llm` | off | static detector only |
| `--diff REF` | | scan only `.py` files changed against `REF`, and only functions that overlap changed lines |
| `--model` | `qwen3.5:4b` | Ollama model name |
| `--host` | `$OLLAMA_HOST` or `http://localhost:11434` | |
| `--think` | off | allow hidden reasoning on thinking models (CommentInject runs used `think=false`) |
| `--sarif / --html / --json FILE` | | outputs (`--json -` writes to stdout) |
| `--fail-on` | `blind-spot` | `blind-spot`, `comment`, `any` or `never` |
| `--cache-dir / --no-cache` | `~/.cache/commentguard` | |
| `--backend` | `ollama` | `openai-compatible` is optional and off by default (see below) |

Exit codes: `0` nothing matched `--fail-on`; `1` findings matched; `2` error (for example, Ollama
is unreachable or the model is not pulled).

**Optional remote backend (off by default).** To review with any OpenAI-compatible
`/v1/chat/completions` endpoint, set `COMMENTGUARD_BACKEND=openai-compatible`,
`COMMENTGUARD_API_BASE=https://host/v1` and `COMMENTGUARD_API_KEY=...`, then pass `--model`.
Your code is sent to that endpoint. CommentGuard never uses this backend unless you configure it.
It was not used in the evaluation below.

## Integrations

**GitHub Action** (`action.yml`, composite). It scans the Python files changed in a push or pull
request, writes SARIF and uploads it to code scanning. Blind spots then show up as alerts on the
PR. Set `scan-all: "true"` to scan every file under `paths` instead of only changed files.
See [`examples/github-workflow.yml`](examples/github-workflow.yml).

```yaml
- uses: actions/checkout@v5
  with: { fetch-depth: 0 }
- uses: sunny-chokshi/commentguard@v0.1.0
  with:
    mode: static          # or 'ollama': installs Ollama in the runner and pulls `model`
    fail-on: comment
```

The job needs `permissions: security-events: write`. The `ollama` mode downloads a model of about
3 GB on each run unless you cache it, so `static` is the practical default for CI. Run the
differential review locally or on a self-hosted runner that already has Ollama.

**pre-commit** (`.pre-commit-hooks.yaml`, static mode only, no model calls):

```yaml
repos:
  - repo: https://github.com/sunny-chokshi/commentguard
    rev: v0.1.0
    hooks:
      - id: commentguard
```

**SARIF rules:** `CG001` comment-induced blind spot (error), `CG002` LLM flags function as
vulnerable (warning, an unverified AI opinion), `CG101` to `CG104` assurance comment by family
(note).

## Evaluation summary

Run on all 756 cases of the subset derived from the 840-case CommentInject v2.0.0-rc3 dataset with `qwen3.5:4b` (Ollama, temperature 0,
`think=false`, one run). The as-written verdicts reproduced the published CommentInject v2 run on
756/756 cases. Two fixed twins in this subset (V23 and V27) were subsequently revised. These exploratory results use the original rc3 versions and reference labels.

| | Result |
|---|---|
| Static detector recall, benchmark adversarial comments (in-sample: rules written with these strategies in view) | 594/648 = 91.7% (11 of 12 strategies at 100%, `distraction_comment` at 0%) |
| Static detector false alarms, benign doc comments | 0/54 |
| **Static detector recall, held-out assurance comments** written after the rules were frozen | **5/32 = 15.6%** (0/40 benign false alarms) |
| As-written review missed the bug (vulnerable twin + adversarial comment) | 54/324 |
| **Of those misses, flagged as a comment-induced blind spot** | **54/54** |
| **False blind spots on adversarial cases labelled fixed in rc3** (324 cases = 27 fixed functions × 12 strategies) | **53/324 = 16.4%** |

Read these together. On this benchmark the stripped code is exactly the clean twin, and the model
flags every vulnerable clean twin, so catching all 54 misses follows by construction. It is not a
general detection rate. The cost is false alarms: the 4B model wrongly flags 41% of fixed clean
twins, so about half of the blind-spot alarms on adversarial cases (53/107) point at cases labelled
fixed in rc3. The static regex detector generalizes poorly to new phrasings. The differential
check, not the regex list, is the main feature.

Full numbers, the method and raw outputs: [`eval/RESULTS.md`](eval/RESULTS.md).

## Limitations

* **Python only.** Units are top-level functions and methods of top-level classes. Nested
  functions are reviewed as part of their parent.
* **The static detector is a pattern matcher.** It recognises the phrasings it was written for and
  misses many new ones. The held-out numbers in `eval/RESULTS.md` show how large that gap is.
  Treat it as a cheap first pass, not as coverage.
* **The differential check inherits the model's blind spots.** If the model misses the bug even
  without comments, there is no flip to detect. If the model wrongly flags safe code once the
  comments are removed, you get a false blind spot.
* **Small local models are brittle.** Unrelated edits, such as an extra import line, can change
  a verdict. A "blind spot" is evidence that comments influenced this model on this code. It does
  not prove that a vulnerability exists. Confirm by reading the code.
* **A clean report does not mean the code is secure.**
* The evaluation uses the author's own benchmark, one model and one run. See `eval/RESULTS.md`.

## What existed before CommentGuard and what was built for this entry

CommentInject v1 predates the event. CommentInject v2 and `commentinject-skill` were created on
Nov 24, 2026, inside the event window (Nov 21-28), as separate projects. They are disclosed here and
are not counted as this entry's new work. CommentGuard itself was built on Nov 25, 2026.

**Pre-existing work, not part of this entry's new work:**

* The CommentInject v1 and v2 datasets, papers and experiment scripts (Sunny Chokshi). These are
  the research basis: the attack taxonomy, the reviewer prompt, the benchmark cases and the
  finding that comments flip LLM verdicts.
* The `commentinject-skill` repository, first commit Nov 24, 2026, 20:44 US Eastern (Nov 25 UTC).
  It is a prompt-level agent skill that tells an AI reviewer to set assurance comments aside. It
  also ships a small regex comment scanner (`scripts/scan_comments.py`, about 200 lines, the same
  four families, Markdown/JSON output). So **flagging assurance comments by pattern is not new in
  CommentGuard.** CommentGuard's detector is a separate implementation; no code was copied from
  the skill. The skill has no differential review, no SARIF or HTML output, no CI integration and
  no evaluation harness.

**Built during the hackathon (this repository, first commit Nov 25, 2026):**

* The `commentguard` package: unit extraction, comment and docstring stripping, the four-family
  assurance-comment detector, differential review with outcome classification, the Ollama backend
  and optional OpenAI-compatible backend, the disk cache, `--diff` mode and `--fail-on` policies.
* Terminal, SARIF 2.1.0, HTML and JSON outputs.
* The GitHub Action, pre-commit hook and example configs.
* The evaluation harness (`eval/run_eval.py`), the dev and held-out comment sets, and the results.
* The tests, demo files and demo script.

A few functions were copied from CommentInject v2 with attribution: the reviewer prompt, the
verdict parser and the tokenizer-based comment stripper. See [`ATTRIBUTION.md`](ATTRIBUTION.md).
The git history in this repository shows the build.

## AI disclosure

CommentGuard was built with AI assistance. Claude Code (Anthropic) wrote most of the code, tests
and documentation under the author's direction. The author set the design, the scope and the
evaluation protocol, and reviewed the results. The tool itself uses a local LLM (via Ollama) as
the security reviewer whose behaviour it checks.

## License and citation

MIT License, Copyright (c) 2026 Sunny Chokshi. See [`LICENSE`](LICENSE). The CommentInject data
used in the evaluation is CC BY 4.0 and is read from a local checkout, not redistributed here.

If you use CommentGuard in research, please cite CommentInject v2
(doi:10.5281/zenodo.24517927).
