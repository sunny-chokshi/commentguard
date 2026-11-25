"""Evaluate CommentGuard on the CommentInject v2 CORE benchmark (27 pairs, 756 cases).

Runs the same pipeline as `commentguard scan` (unit extraction, static detector, differential
review) on every case and reports:
  * static detector: recall on adversarial cases (by strategy/family) and false-alarm rate on
    clean and doc cases; plus a small hand-written held-out comment set (eval/heldout_comments.jsonl)
  * differential check: among vulnerable-twin cases where the as-is review says SAFE (a miss), the
    fraction flagged as a comment-induced blind spot; and the false blind-spot rate on fixed twins.

Usage:
  python3 eval/run_eval.py --model qwen3.5:4b [--limit N] [--pairs V01 V02 ...]
      [--cases /path/to/CommentInject_v2/data/cases.jsonl] [--static-only]
Resumable: per-case results are appended to eval/results/raw_<model>.jsonl and reused.
"""
import argparse
import collections
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from commentguard.llm import OllamaBackend, Reviewer  # noqa: E402
from commentguard.patterns import detect  # noqa: E402
from commentguard.scan import BLIND_SPOT, scan_source  # noqa: E402
from commentguard.source import collect_comments  # noqa: E402

DEFAULT_CASES = ("<commentinject-v2 checkout>/"
                 "data/cases.jsonl")


def load_jsonl(p):
    with open(p) as f:
        return [json.loads(l) for l in f if l.strip()]


def pct(n, d):
    return f"{n}/{d} ({100.0 * n / d:.1f}%)" if d else f"{n}/0 (n/a)"


def wilson(n, d, z=1.96):
    if not d:
        return (0.0, 0.0)
    p = n / d
    den = 1 + z * z / d
    c = (p + z * z / (2 * d)) / den
    h = z * ((p * (1 - p) / d + z * z / (4 * d * d)) ** 0.5) / den
    return (max(0.0, c - h), min(1.0, c + h))


def ci(n, d):
    lo, hi = wilson(n, d)
    return f"[{100 * lo:.1f}, {100 * hi:.1f}]"


def static_eval(cases):
    out = {}
    by_cond = collections.defaultdict(lambda: [0, 0])
    by_strat = collections.defaultdict(lambda: [0, 0])
    by_fam_strat = collections.defaultdict(lambda: [0, 0])
    family_correct = [0, 0]
    for c in cases:
        f = detect(collect_comments(c["code"]))
        hit = bool(f)
        by_cond[c["condition"]][0] += hit
        by_cond[c["condition"]][1] += 1
        if c["condition"] == "adversarial":
            by_strat[c["strategy"]][0] += hit
            by_strat[c["strategy"]][1] += 1
            fam = c["family"]
            by_fam_strat[fam][0] += hit
            by_fam_strat[fam][1] += 1
            if hit:
                family_correct[1] += 1
                family_correct[0] += fam in {x["family"] for x in f}
    out["by_condition"] = {k: v for k, v in by_cond.items()}
    out["by_strategy"] = dict(by_strat)
    out["by_family"] = dict(by_fam_strat)
    out["family_label_correct_among_hits"] = family_correct
    return out


def heldout_eval(path):
    rows = load_jsonl(path)
    res = {"assurance": [0, 0], "benign": [0, 0], "benign_security": [0, 0], "misses": [], "false_alarms": []}
    for r in rows:
        hit = bool(detect(collect_comments(r["comment"])))
        key = "assurance" if r["label"] == "assurance" else "benign"
        res[key][0] += hit
        res[key][1] += 1
        if key == "benign" and r.get("security_related"):
            res["benign_security"][0] += hit
            res["benign_security"][1] += 1
        if key == "assurance" and not hit:
            res["misses"].append(r["comment"])
        if key == "benign" and hit:
            res["false_alarms"].append(r["comment"])
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=DEFAULT_CASES)
    ap.add_argument("--model", default="qwen3.5:4b")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--pairs", nargs="*")
    ap.add_argument("--static-only", action="store_true")
    ap.add_argument("--strategies", default=os.path.join(os.path.dirname(DEFAULT_CASES), "strategies.jsonl"))
    a = ap.parse_args()

    cases = load_jsonl(a.cases)
    fam = {s["strategy"]: s["family"] for s in load_jsonl(a.strategies)}
    for c in cases:
        c["family"] = fam.get(c["strategy"], "none")
    conds = {"clean", "doc", "adversarial"}
    cases = [c for c in cases if c["condition"] in conds]
    if a.pairs:
        cases = [c for c in cases if c["pair_id"] in set(a.pairs)]
    if a.limit:
        cases = cases[:a.limit]

    summary = {"cases_file": a.cases, "n_cases": len(cases),
               "n_pairs": len({c["pair_id"] for c in cases}),
               "static": static_eval(cases)}
    for key, name in (("dev", "dev_comments.jsonl"), ("heldout", "heldout_comments.jsonl")):
        pth = os.path.join(HERE, name)
        if os.path.exists(pth):
            summary[key] = heldout_eval(pth)

    if not a.static_only:
        backend = OllamaBackend(a.model, think=False, seed=0)
        ident = backend.identity()
        summary["reviewer"] = ident
        reviewer = Reviewer(backend, os.path.join(HERE, "cache"))
        os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
        raw_path = os.path.join(HERE, "results", f"raw_{a.model.replace(':', '-').replace('/', '_')}.jsonl")
        done = {}
        if os.path.exists(raw_path):
            done = {r["case_id"]: r for r in load_jsonl(raw_path) if r.get("model_digest") == ident["digest"]}
        rows = []
        t0 = time.time()
        with open(raw_path, "a") as fout:
            for i, c in enumerate(cases, 1):
                if c["case_id"] in done:
                    rows.append(done[c["case_id"]])
                    continue
                units, err = scan_source(c["code"], c["case_id"] + ".py", reviewer)
                assert not err and len(units) == 1, (c["case_id"], err, len(units))
                u = units[0]
                rev = u["review"]
                row = {k: c[k] for k in ("case_id", "pair_id", "cwe", "variant", "label", "condition", "strategy",
                                         "family")}
                row.update(model=a.model, model_digest=ident["digest"],
                           static_hit=bool(u["assurance"]),
                           static_families=sorted({f["family"] for f in u["assurance"]}),
                           status=rev["status"], asis=rev["asis"]["verdict"], stripped=rev["stripped"]["verdict"],
                           asis_response=rev["asis"]["response"], stripped_response=rev["stripped"]["response"],
                           stripped_equals_clean_twin=None)
                rows.append(row)
                fout.write(json.dumps(row) + "\n")
                fout.flush()
                if i % 50 == 0:
                    el = time.time() - t0
                    print(f"  {i}/{len(cases)}  {el / 60:.1f} min, model calls {reviewer.calls}", flush=True)
        summary["model_calls_this_run"] = reviewer.calls
        summary["cache_hits_this_run"] = reviewer.hits
        summary["differential"] = differential(rows, cases)
        summary["raw_file"] = os.path.relpath(raw_path, os.path.dirname(HERE))

    out = os.path.join(HERE, "results", f"summary_{a.model.replace(':', '-')}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(summary, f, indent=2)
    print_report(summary)
    print(f"\nwrote {out}")


def differential(rows, cases):
    """Differential-check metrics. Uses the case code to verify stripped view == clean twin."""
    from commentguard.source import strip_all
    code = {c["case_id"]: c["code"] for c in cases}
    clean = {(c["pair_id"], c["variant"]): c["code"] for c in cases if c["condition"] == "clean"}
    d = {}
    eq = [0, 0]
    for r in rows:
        if r["condition"] != "clean" and (r["pair_id"], r["variant"]) in clean:
            eq[1] += 1
            eq[0] += strip_all(code[r["case_id"]]).strip() == strip_all(clean[(r["pair_id"], r["variant"])]).strip()
    d["stripped_equals_clean_twin"] = eq

    def sel(**kw):
        return [r for r in rows if all((r[k] in v) if isinstance(v, (set, list, tuple)) else r[k] == v
                                       for k, v in kw.items())]

    d["unparsed_responses"] = sum((r["asis"] == "UNPARSED") + (r["stripped"] == "UNPARSED") for r in rows)
    for cond_name, cond in (("adversarial", {"adversarial"}), ("doc", {"doc"}), ("clean", {"clean"}),
                            ("adversarial+doc", {"adversarial", "doc"})):
        vul = sel(variant="vulnerable", condition=cond)
        miss = [r for r in vul if r["asis"] != "VULNERABLE"]
        caught = [r for r in miss if r["status"] == BLIND_SPOT]
        safe = sel(variant="safe", condition=cond)
        false_bs = [r for r in safe if r["status"] == BLIND_SPOT]
        vul_bs = [r for r in vul if r["status"] == BLIND_SPOT]
        d[cond_name] = {"vulnerable_cases": len(vul), "asis_flagged": len(vul) - len(miss),
                        "asis_wrong_safe": len(miss), "caught_as_blind_spot": len(caught),
                        "safe_cases": len(safe), "false_blind_spots_on_fixed": len(false_bs),
                        "safe_asis_flagged": sum(1 for r in safe if r["asis"] == "VULNERABLE"),
                        "blind_spots_on_vulnerable": len(vul_bs)}
    # per strategy (adversarial)
    ps = {}
    for r in sel(condition="adversarial"):
        s = ps.setdefault(r["strategy"], {"family": r["family"], "vul": 0, "miss": 0, "caught": 0, "safe": 0,
                                          "false_bs": 0})
        if r["variant"] == "vulnerable":
            s["vul"] += 1
            if r["asis"] != "VULNERABLE":
                s["miss"] += 1
                s["caught"] += r["status"] == BLIND_SPOT
        else:
            s["safe"] += 1
            s["false_bs"] += r["status"] == BLIND_SPOT
    d["per_strategy"] = ps
    # combined (static OR differential) on adversarial vulnerable misses
    miss = [r for r in sel(variant="vulnerable", condition="adversarial") if r["asis"] != "VULNERABLE"]
    d["adv_miss_static_or_diff"] = [sum(1 for r in miss if r["static_hit"] or r["status"] == BLIND_SPOT), len(miss)]
    d["adv_miss_static"] = [sum(1 for r in miss if r["static_hit"]), len(miss)]
    # baseline review accuracy on clean twins
    cv = sel(variant="vulnerable", condition="clean")
    cs = sel(variant="safe", condition="clean")
    d["clean_baseline"] = {"vulnerable_flagged": [sum(r["asis"] == "VULNERABLE" for r in cv), len(cv)],
                           "safe_flagged": [sum(r["asis"] == "VULNERABLE" for r in cs), len(cs)]}
    # misses not catchable because the model also misses the clean twin
    clean_flag = {r["pair_id"]: r["asis"] == "VULNERABLE" for r in cv}
    adv_miss_clean_missed = sum(1 for r in miss if not clean_flag.get(r["pair_id"], False))
    d["adv_miss_where_clean_twin_also_missed"] = adv_miss_clean_missed
    return d


def print_report(s):
    st = s["static"]
    print(f"\nCases: {s['n_cases']} ({s['n_pairs']} pairs)")
    print("\nStatic detector (any assurance finding in the case):")
    for k in ("adversarial", "doc", "clean"):
        if k in st["by_condition"]:
            n, d = st["by_condition"][k]
            print(f"  {k:12s} {pct(n, d)}  95% CI {ci(n, d)}")
    print("  by strategy:")
    for k, (n, d) in sorted(st["by_strategy"].items()):
        print(f"    {k:22s} {pct(n, d)}")
    print("  by family:")
    for k, (n, d) in sorted(st["by_family"].items()):
        print(f"    {k:22s} {pct(n, d)}")
    n, d = st["family_label_correct_among_hits"]
    print(f"  family label correct among hits: {pct(n, d)}")
    for key, label in (("dev", "Dev comment set (used to tune the rules; in-sample)"),
                       ("heldout", "Held-out comment set (written after tuning; rules not changed since)")):
        if key not in s:
            continue
        h = s[key]
        print(f"\n{label}:")
        print(f"  assurance recall        {pct(*h['assurance'])}  CI {ci(*h['assurance'])}")
        print(f"  benign false alarms     {pct(*h['benign'])}  CI {ci(*h['benign'])}")
        print(f"   of which security-related benign {pct(*h['benign_security'])}")
        for m in h["misses"]:
            print(f"   miss: {m}")
        for m in h["false_alarms"]:
            print(f"   false alarm: {m}")
    if "differential" in s:
        d = s["differential"]
        r = s["reviewer"]
        print(f"\nDifferential review: {r['model']} digest {r['digest'][:12]} temp 0 think={r['think']} seed {r['seed']}")
        print(f"  stripped view identical to clean twin: {pct(*d['stripped_equals_clean_twin'])}")
        cb = d["clean_baseline"]
        print(f"  clean baseline: vulnerable flagged {pct(*cb['vulnerable_flagged'])}, "
              f"fixed flagged {pct(*cb['safe_flagged'])}")
        for k in ("adversarial", "doc", "adversarial+doc", "clean"):
            x = d[k]
            print(f"  [{k}] vulnerable twins: {x['vulnerable_cases']}, as-is wrong SAFE: {x['asis_wrong_safe']}, "
                  f"caught as blind spot: {pct(x['caught_as_blind_spot'], x['asis_wrong_safe'])} "
                  f"CI {ci(x['caught_as_blind_spot'], x['asis_wrong_safe'])}")
            print(f"  [{k}] fixed twins: {x['safe_cases']}, false blind spots: "
                  f"{pct(x['false_blind_spots_on_fixed'], x['safe_cases'])} "
                  f"CI {ci(x['false_blind_spots_on_fixed'], x['safe_cases'])}")
        print(f"  adversarial misses where the clean twin was also missed: {d['adv_miss_where_clean_twin_also_missed']}")
        print(f"  adversarial misses flagged by static OR differential: {pct(*d['adv_miss_static_or_diff'])}")
        print(f"  unparsed responses: {d['unparsed_responses']}")
        print("  per strategy (adversarial): misses caught / misses ; false blind spots / fixed")
        for k, v in sorted(d["per_strategy"].items()):
            print(f"    {k:22s} {v['caught']}/{v['miss']} ; {v['false_bs']}/{v['safe']}")


if __name__ == "__main__":
    main()
