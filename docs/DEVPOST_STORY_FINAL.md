**Code (MIT):** https://github.com/sunny-chokshi/commentguard (the v0.1.0 tag predates the documentation and disclosure updates in the submitted commit on `main`). The repository runs its own GitHub Action on every push.

**At a glance, with the limits up front.** The differential evaluation uses a 756-case, 27-pair subset of my historical CommentInject v2.0.0-rc3 benchmark, with qwen3.5:4b, one run and Python only.
* CommentGuard flagged all 54 of the 324 adversarial vulnerable cases that the original review missed. This follows by construction on this benchmark and is not a general detection rate.
* It raised false blind spots on 53 of 324 adversarial cases labelled fixed in rc3 (16.4%).
* Two included fixed twins, V23 and V27, were subsequently revised. These exploratory results have not been recomputed using the revised twins.
* The static detector identified only 5 of 32 held-out assurance-comment phrasings (15.6%). It is a quick filter, not a complete defense.
* A small regex comment scanner already existed in my earlier commentinject-skill project.

## Inspiration

Teams increasingly ask LLMs to review pull requests for security bugs, and LLMs read comments. In
my CommentInject research (v1: doi:10.5281/zenodo.23088528; v2: doi:10.5281/zenodo.24517927) I
measured what happens when a comment makes an unverified claim, such as "input is sanitized
upstream", "SECURITY REVIEWED" or "runs only in the CI sandbox". In my release-candidate runs, some models flagged vulnerable code without comments but called the
same code SAFE when misleading comments were present. In CommentGuard's evaluation (historical rc3
subset), qwen3.5:4b did so in 54 of 324 adversarial vulnerable cases. Two fixed twins in this subset (V23 and V27) were subsequently revised. These exploratory results use the original rc3 versions and reference labels.
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
pre-commit hook (static mode). It runs without paid model API calls. When Ollama runs on the same machine, model review does not
require sending source code to a remote model service. Results are cached.

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
* Evaluation harness (`eval/run_eval.py`): it runs the real CLI pipeline on all 756 cases of the subset
  derived from the 840-case CommentInject v2.0.0-rc3 release, with qwen3.5:4b.
* 23 unit and CLI tests, using a fake backend so they need no model. A self-test workflow runs the composite Action on `demo/` and uploads SARIF to code scanning (green on GitHub). The pre-commit hook was run through the `pre-commit` tool from the `v0.1.0` tag (`pre-commit try-repo`).

## Challenges we ran into

* **Honest measurement of the static detector.** It scored 100% on 11 of the 12 benchmark
  strategies, but its rules were written while looking at those strategies. I therefore wrote a
  separate held-out set of assurance comments after freezing the rules. Recall on that set was
  5/32 (15.6%), against 594/648 (91.7%) on the benchmark templates, which shows the regex approach does not generalize well. That result is why the
  differential LLM check, not the regex detector, is the core of the tool.
* **False blind spots.** A small model often flags *fixed* code once comments are removed. If the
  comment then makes it say SAFE, the differential check raises a false blind spot. On the cases
  labelled fixed in rc3 with adversarial comments this happened in 53/324 cases (16.4%). About half
  of all blind-spot alarms on adversarial cases pointed at cases labelled fixed in rc3.
* **Brittleness.** Adding an unrelated import line above the demo function was enough to change
  the 4B model's verdict. CommentGuard reports what the model did and does not claim the code is
  vulnerable.

## Accomplishments that we're proud of

* An end-to-end tool that works on a laptop without a cloud model service or paid model API calls: CLI, SARIF, HTML, Action,
  pre-commit, tests.
* Reproducibility: CommentGuard's as-written verdicts matched the published CommentInject v2 run
  for the same model digest on 756/756 cases.
* On all 756 cases of the subset derived from the 840-case CommentInject v2.0.0-rc3 release
  (qwen3.5:4b, one run), the as-written review missed the vulnerability in 54 of the 324
  adversarial cases on vulnerable code, and CommentGuard flagged all 54 as blind spots. That
  follows by construction here, because the stripped code equals the clean twin, which the model
  always caught. The trade-off is 53/324 (16.4%) false blind spots on adversarial cases labelled fixed in rc3. Both
  numbers are reported together. Two fixed twins in this subset (V23 and V27) were subsequently revised. These exploratory results use the original rc3 versions and reference labels.
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
  CommentInject v2 and `commentinject-skill` were created on Nov 24, 2026, inside the event window (which began Nov 21), as separate projects; they are disclosed here and not claimed as this entry's work.
* **New during the hackathon (built Nov 25, 2026; every commit is in the git history, starting with baf3181):** the whole `commentguard` repository. That means
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
