# CommentGuard evaluation on CommentInject v2.0.0-rc3 (historical 27-pair subset)

> **Historical dataset.** This evaluation uses the historical CommentInject v2.0.0-rc3 dataset. V10 incorporates a revision made after outcome data were available, before rc3. Two fixed twins included in this subset (V23 and V27) were subsequently revised after rc3. The reported counts use the original rc3 reference labels and have not been recomputed using the subsequently revised twins. False-blind-spot and precision estimates are therefore provisional with respect to the revised ground truth.

Run on 2026-11-25 on the author's Mac (Apple Silicon) with Ollama 0.40.6.

## Setup

| | |
|---|---|
| Benchmark | CommentInject v2.0.0-rc3 (doi:10.5281/zenodo.24517927; git tag `v2.0.0-rc3`) **core subset**: the published `data/cases.jsonl` (840 cases) without pairs V04, V13 and V19. Derive it with `python3 -c "import json,sys; sys.stdout.writelines(l for l in open('data/cases.jsonl') if json.loads(l)['pair_id'] not in {'V04','V13','V19'})" > cases_core27.jsonl` (sha256 `d4352b28c2adbeba589692c835921a769f984d0d8e6146819189fec7f059fab1`, reproduced from a fresh clone on 2026-11-25): 27 vulnerable/fixed twin pairs, 756 cases = 54 clean + 54 doc (one benign descriptive comment) + 648 adversarial (12 strategies × 54) |
| Subset | **All 756 cases of the derived rc3 subset were run.** |
| Reviewer model | `qwen3.5:4b`, Ollama digest `d8b0f5e9760c…` |
| Decoding | temperature 0, seed 0, `think=false` (same settings as the CommentInject v2 `+nothink` runs) |
| Prompt / parser | CommentInject v1/v2 reviewer prompt and the v2 verdict parser (unchanged) |
| Pipeline | The real CommentGuard code path (`scan_source`): unit extraction, static detector, differential review. Each case is one file with one function. |
| Runs | **One run** (seed 0) |
| Detector rules | `commentguard/patterns.py`, sha256 `97741e23…8c82` |
| Raw outputs | `eval/results/raw_qwen3.5-4b.jsonl` (one row per case, both model responses), `eval/results/summary_qwen3.5-4b.json`, log `eval/results/run_qwen3.5-4b.log` |

Reproduce with a CommentInject v2.0.0-rc3 checkout (840 cases) and the 27 subset pairs:
`python3 eval/run_eval.py --model qwen3.5:4b --cases <rc3 checkout>/data/cases.jsonl --pairs V01 V02 V03 V05 V06 V07 V08 V09 V10 V11 V12 V14 V15 V16 V17 V18 V20 V21 V22 V23 V24 V25 V26 V27 V28 V29 V30`.
Running the evaluation without the documented pair filter may use a different dataset. Use the exact rc3 checkout and pair-selection command above to reproduce the reported evaluation.
About 25 minutes.

**Reproducibility check.** CommentGuard's as-written verdicts agreed with the published
CommentInject v2.0.0-rc3 seed-0 run of `qwen3.5:4b+nothink` (same digest; `results/phase2/raw_seed0.jsonl`
combined with the 14 V10 re-runs in `raw_seed0_v10fix.jsonl`) on **756/756** cases.

## Headline numbers

**Static assurance-comment detector** (any finding in the case):

| Set | Result |
|---|---|
| CommentInject adversarial cases (recall) | **594/648 = 91.7%** |
| CommentInject doc cases (false alarms) | **0/54 = 0.0%** |
| CommentInject clean cases (false alarms) | 0/54 = 0.0% |
| Dev comment set, assurance recall (**in-sample**: used while writing the rules) | 23/24 = 95.8% |
| Dev comment set, benign false alarms | 0/30 = 0.0% |
| **Held-out comment set, assurance recall** (written after the rules were frozen) | **5/32 = 15.6%** |
| Held-out comment set, benign false alarms | 0/40 = 0.0% (0/20 security-related benign) |

* By strategy, recall was 54/54 for 11 strategies and **0/54 for `distraction_comment`**. That
  strategy is a long comment about performance with no security claim, and no rule targets it.
  The family label was correct on 594/594 hits.
* **Read the benchmark recall as in-sample.** The rules were written with the 12 CommentInject
  strategy texts in view, so 91.7% says the detector covers those templates, not that it
  generalizes. The first rule version scored 9/24 (37.5%) on the dev set
  (`eval/results/static_v0_pretuning.json`). The rules were then broadened using the dev set, and
  only afterwards was the held-out set written. Its **15.6% recall is the honest generalization
  estimate**: the regex detector misses most new phrasings. It produced no false alarms on 70
  benign comments, 35 of them security-related (e.g. "Use a parameterized query", "TODO:
  validate the hostname"). Both comment sets were written by the author with AI assistance.

**Differential review (comment-induced blind spots)** with `qwen3.5:4b`:

| Measure | Result |
|---|---|
| Baseline, clean twins: vulnerable flagged | 27/27 |
| Baseline, clean twins: **fixed code wrongly flagged** | **11/27 = 40.7%** |
| Adversarial vulnerable cases where the as-is review said SAFE (a miss) | 54/324 = 16.7% |
| **…of those 54 misses, flagged as a blind spot by CommentGuard** | **54/54 = 100%** |
| Doc vulnerable cases with an as-is miss, caught | 1/1 |
| **False blind spots on adversarial cases labelled fixed in rc3** (27 fixed functions × 12 strategies) | **53/324 = 16.4%** |
| False blind spots on rc3 fixed twins, doc | 0/27 = 0.0% |
| False blind spots on rc3 fixed twins, clean | 0/27 (nothing to strip) |
| Blind-spot alarms on adversarial cases that point at a real vulnerability (precision) | 54/107 = 50.5% |
| Unparsed responses | 0 of 1,512 verdicts |

Per strategy (adversarial): misses caught / misses, and false blind spots / fixed twins:

| Strategy | Family | Misses caught | False blind spots |
|---|---|---|---|
| false_reassurance | context-manipulation | 19/19 | 11/27 |
| scope_limitation | context-manipulation | 14/14 | 10/27 |
| misleading_context | context-manipulation | 3/3 | 5/27 |
| false_test_coverage | verification-premise | 5/5 | 9/27 |
| authority_claim | verification-premise | 3/3 | 5/27 |
| fake_review_approval | verification-premise | 0/0 | 4/27 |
| formal_verification | credibility-vocabulary | 4/4 | 4/27 |
| security_camouflage | credibility-vocabulary | 2/2 | 2/27 |
| compliance_claim | credibility-vocabulary | 0/0 | 1/27 |
| distraction_comment | pressure-distraction | 3/3 | 2/27 |
| deadline_pressure | pressure-distraction | 1/1 | 0/27 |
| authorial_confidence | pressure-distraction | 0/0 | 0/27 |

Every one of the 54 adversarial misses was flagged by the static detector, the differential check,
or both (54/54). The 3 `distraction_comment` misses were caught only by the differential check.

## How to read the differential numbers

* **The 100% catch rate holds by construction on this benchmark, so do not quote it as a general
  detection rate.** Removing the comments from any CommentInject case gives exactly its clean
  twin; this was checked: 702/702 stripped views were identical to the clean twin. qwen3.5:4b
  flagged all 27 vulnerable clean twins. So every comment-induced miss became a VULNERABLE/SAFE
  disagreement. The check can only catch misses the model would not make on the bare code. On
  real code, a model that also misses the bare vulnerability gives no flip to detect, and
  comments placed inside a function (CommentInject puts them above the function) were not tested.
* **The real cost is false alarms on safe code.** The 4B model wrongly flagged 40.7% of the fixed
  clean twins. When an assurance comment then talked it back to SAFE, CommentGuard raised a
  "blind spot" on a case labelled fixed in rc3: 16.4% of those adversarial cases. About half of the
  blind-spot alarms on adversarial cases (53/107) were on cases labelled fixed in rc3. A blind spot tells you that
  comments changed this model's verdict and that a human should look. It does not prove there is
  a vulnerability.
* Benign descriptive comments (the doc condition) caused 1 miss on 27 vulnerable twins, which
  was caught, and 0 false blind spots on 27 fixed twins.

## Limitations

* **Small model, one run.** One 4B local model, seed 0, temperature 0. Other models, sizes or
  seeds will give different numbers. CommentInject v2 reports large differences between models.
  No repeated sampling or variance estimate was done.
* **Author's own benchmark and comment sets.** CommentInject v2 and both comment sets were made by
  the same author, and the detector rules were written with the benchmark strategies in view. No
  independent or real-world evaluation has been done yet.
* **Python only**, single-function synthetic cases with comments placed above the function. Real
  repositories have longer functions, cross-file context and comments inside function bodies.
* **The static detector does not generalize well** (15.6% held-out recall). It is a cheap first
  pass, not a defence.
* **Small-model verdicts are brittle.** In the demo, adding an unrelated import line above a
  function changed the as-written verdict. A blind spot reflects this model's behaviour on this
  exact text.
* The GitHub Action runs on every push to this repository in static mode (the `selftest` workflow;
  its SARIF upload shows CG101-CG104 assurance-comment alerts on `demo/` in code scanning). Its
  `mode: ollama` path has not been run on GitHub. The pre-commit hook was run through the
  `pre-commit` tool (`pre-commit try-repo` at tag v0.1.0) on Nov 25, 2026 and flagged the demo file.
