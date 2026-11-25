**Code (MIT):** https://github.com/sunny-chokshi/commentguard (v0.1.0). The repository runs its own GitHub Action on every push.

**At a glance, with the limits up front.** All numbers come from my own CommentInject v2 benchmark (756 core cases, qwen3.5:4b, one run, Python only):
* The differential check flagged all 54 cases where a comment hid a real bug. This follows by construction on this benchmark.
* It also raised **false blind spots on 53 of 324 already-fixed functions (16.4%)**.
* The static regex detector caught **only 5 of 32 held-out phrasings (15.6%)** that I wrote after freezing its rules. It is a quick filter, not the defence.
* A small regex comment scanner already existed in my earlier `commentinject-skill`. See the development disclosure at the end.

## Inspiration

Teams increasingly ask LLMs to review pull requests for security bugs, and LLMs read comments. In
my CommentInject research (v1: doi:10.5281/zenodo.23088528; v2: doi:10.5281/zenodo.24517927) I
measured what happens when a comment makes an unverified claim, such as "input is sanitized
upstream", "SECURITY REVIEWED" or "runs only in the CI sandbox". Small open models that caught a
SQL injection in bare code often called the same code SAFE once one of those comments was added.
The benchmark showed the problem. I wanted a tool a developer can run on their own code before
merge.

## What it does

CommentGuard scans Python code (`commentguard scan PATH [--diff REF]`) in two ways:

1. **Differential AI review (the core).** Each function goes to a local LLM reviewer twice: once
   as written, and once with every comment and docstring removed. The code is otherwise identical.
   If the stripped version is called VULNERABLE and the commented version SAFE, the comments
   changed the verdict. CommentGuard reports a **comment-induced blind spot** and fails the build.
   It also reports when both views agree.
2. **Static assurance-comment detector.** Regex rules in four families (verification claims,
   context claims, credibility vocabulary, pressure/distraction) flag comments that assert
   security properties. It is fast and needs no model, so it runs in pre-commit.

Outputs: a coloured terminal summary, SARIF 2.1.0 for GitHub code scanning, a self-contained
HTML report with side-by-side "as written" and "stripped" verdicts and highlighted comments, and
JSON. Integrations: a composite GitHub Action that scans changed files and uploads SARIF, and a
pre-commit hook (static mode). Everything runs locally with Ollama at no cost, and results are
cached.

## How we built it

* Python 3 standard library only: no runtime dependencies.
* `ast` splits files into review units. Python's `tokenize` removes comments correctly even when
  `#` appears inside strings. Docstrings are removed through the AST and replaced with `pass`
  when needed, so the stripped code still parses.
* The reviewer prompt and verdict parser are taken unchanged from CommentInject v2, so the results
  are comparable with the benchmark. Calls go to Ollama at temperature 0 with a fixed seed and
  `think=false`. A disk cache keyed by model digest, prompt version and exact code makes re-runs
  instant.
* SARIF uses stable fingerprints and related locations that point at the comment that caused the
  blind spot. The GitHub Action runs `--diff` against the PR base.
* Evaluation harness (`eval/run_eval.py`): it runs the real CLI pipeline on all 756 CommentInject
  v2 core cases with qwen3.5:4b.
* 23 unit and CLI tests, using a fake backend so they need no model. A self-test workflow runs the composite Action on `demo/` and uploads SARIF to code scanning (green on GitHub). The pre-commit hook was tested from the `v0.1.0` tag.

## Challenges we ran into

* **Honest measurement of the static detector.** It scored 100% on 11 of the 12 benchmark
  strategies, but its rules were written while looking at those strategies. I therefore wrote a
  separate held-out set of assurance comments after freezing the rules. Recall on that set was
  5/32 (15.6%), against 594/648 (91.7%) on the benchmark templates, which shows the regex approach does not generalize well. That result is why the
  differential LLM check, not the regex detector, is the core of the tool.
* **False blind spots.** A small model often flags *fixed* code once comments are removed. If the
  comment then makes it say SAFE, the differential check raises a false blind spot. On the fixed
  twins with adversarial comments this happened in 53/324 cases (16.4%). About half of all
  blind-spot alarms on adversarial cases pointed at code that was already fixed.
* **Brittleness.** Adding an unrelated import line above the demo function was enough to change
  the 4B model's verdict. CommentGuard reports what the model did and does not claim the code is
  vulnerable.

## Accomplishments that we're proud of

* An end-to-end tool that works on a laptop with no cloud and no cost: CLI, SARIF, HTML, Action,
  pre-commit, tests.
* Reproducibility: CommentGuard's as-written verdicts matched the published CommentInject v2 run
  for the same model digest on 756/756 cases.
* On all 756 CommentInject v2 core cases (qwen3.5:4b, one run), the as-written review missed the
  vulnerability in 54/324 adversarial cases, and CommentGuard flagged all 54 as blind spots. That
  follows by construction here, because the stripped code equals the clean twin, which the model
  always caught. The trade-off is 53/324 (16.4%) false blind spots on fixed code. Both numbers are
  reported together.
* Limitations are written down next to the numbers.

## What we learned

* Comparing two views of the same code is a simple, model-agnostic way to make a prompt-injection
  style weakness visible to developers without a second "judge" model.
* On this benchmark, the stripped view of each case is exactly its clean twin. So the
  differential check catches a comment-induced miss whenever the model catches the bare code. Its
  cost is false alarms on safe code that the model over-flags.
* A pattern list is a weak defence on its own: new phrasings slip through.

## What's next

* More languages (JavaScript/TypeScript, Java, Go) using tree-sitter.
* Repeated sampling and several reviewer models, to separate real flips from noise.
* Ways to cut false blind spots, for example asking for agreement across two models before failing
  a build.
* Evaluation on real repositories and on comments not written by the author. All current numbers
  come from the author's own benchmark and comment sets.

## Development disclosure (pre-existing vs. new)

* **Pre-existing:** the CommentInject v1 and v2 datasets, papers and experiment scripts (author's
  own research). Also the `commentinject-skill` repository (first commit Nov 24, 2026 US Eastern),
  a prompt-level agent skill that **also includes a small regex comment scanner** for the same
  four families. Flagging assurance comments by pattern therefore existed before CommentGuard.
* **New during the hackathon (Nov 25-28, 2026):** the whole `commentguard` repository. That means
  the differential review and its outcome classification, a new implementation of the detector
  (no code copied from the skill), docstring stripping, `--diff` mode, the cache, the SARIF, HTML
  and JSON outputs, the GitHub Action, the pre-commit hook, the evaluation harness with dev and
  held-out sets, the tests and the demo.
* Three functions were copied with attribution from CommentInject v2 (MIT): the reviewer prompt,
  the verdict parser and the comment stripper. See `ATTRIBUTION.md`. The git history shows the
  build.

## AI disclosure

Built with AI assistance. Claude Code (Anthropic) wrote most of the code, tests and documentation
under my direction. I set the design, scope and evaluation protocol and reviewed the results.
The tool itself uses a local LLM (qwen3.5:4b via Ollama) as the security reviewer whose behaviour
it checks.
