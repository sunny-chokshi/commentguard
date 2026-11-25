# Attribution

CommentGuard reuses a small amount of code and data design from **CommentInject v2**
(same author, Sunny Chokshi; code MIT, data CC BY 4.0; doi:10.5281/zenodo.24517927).
The CommentInject repository itself was not modified.

| CommentGuard file | What was reused | Source in CommentInject v2 |
|---|---|---|
| `commentguard/llm.py` | `REVIEW_PROMPT` (verbatim; it is the CommentInject v1 Study 1 prompt) and `parse_verdict` (verbatim) | `scripts/common.py` (MIT) |
| `commentguard/source.py` | `strip_comments` (tokenizer-based comment removal, verbatim logic) | `scripts/common.py` (MIT) |
| `commentguard/llm.py` | Ollama request shape (`think=false`, temperature 0, fixed seed) | `scripts/run.py` (MIT) |
| `commentguard/patterns.py` | The four strategy **family names** and the idea of the twelve strategies. The regular expressions are new. | `data/strategies.jsonl` (CC BY 4.0) |
| `eval/run_eval.py` | Reads `data/cases.jsonl` and `data/strategies.jsonl` from a local CommentInject v2 checkout (not copied into this repo) | `data/` (CC BY 4.0) |

Everything else (unit extraction, docstring stripping, the static detector rules, the
differential review and its classification, caching, CLI, SARIF/HTML/JSON output, the GitHub
Action, the pre-commit hook, the evaluation harness and the tests) was written for CommentGuard
during Nov 25-28, 2026.
