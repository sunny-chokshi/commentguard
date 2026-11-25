"""SARIF 2.1.0 output for GitHub code scanning."""
import hashlib
import json

from . import __version__
from .patterns import FAMILIES
from .scan import AGREE_VULN, BLIND_SPOT, NO_COMMENTS

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_FAMILY_IDS = {fam: f"CG10{i + 1}" for i, fam in enumerate(FAMILIES)}


def _rules():
    rules = [{
        "id": "CG001", "name": "CommentInducedBlindSpot",
        "shortDescription": {"text": "Comment-induced blind spot in AI security review"},
        "fullDescription": {"text": "An LLM reviewer flagged this function as VULNERABLE when its comments and "
                                    "docstrings were removed, but called it SAFE with them present. The comments "
                                    "may be steering AI review away from a real vulnerability."},
        "help": {"text": "Verify the security claims in the comments independently, fix the vulnerability the "
                         "stripped review names, or remove unverifiable assurance comments.",
                 "markdown": "Verify the security claims in the comments independently, fix the vulnerability "
                             "the stripped review names, or remove unverifiable assurance comments."},
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "ai-review", "comment-injection"], "precision": "medium",
                       "security-severity": "7.0"},
    }, {
        "id": "CG002", "name": "LLMReviewFlagsVulnerable",
        "shortDescription": {"text": "LLM reviewer flags function as vulnerable"},
        "fullDescription": {"text": "The LLM reviewer called this function VULNERABLE (with and without comments). "
                                    "This is an unverified AI opinion, reported for triage."},
        "help": {"text": "Triage the named vulnerability type; LLM verdicts can be wrong."},
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "ai-review"], "precision": "low", "security-severity": "4.0"},
    }]
    for fam, rid in _FAMILY_IDS.items():
        rules.append({
            "id": rid, "name": "AssuranceComment" + "".join(w.capitalize() for w in fam.split("-")),
            "shortDescription": {"text": f"Security-assurance comment ({fam})"},
            "fullDescription": {"text": FAMILIES[fam] + " Such comments can make AI (and human) reviewers "
                                                        "skip real vulnerabilities (CommentInject v1/v2)."},
            "help": {"text": "Keep claims verifiable (link the test, ticket or audit) or remove them; never rely "
                             "on a comment for a security property."},
            "defaultConfiguration": {"level": "note"},
            "properties": {"tags": ["security", "comment-injection", fam], "precision": "medium"},
        })
    return rules


def _loc(path, line, end_line=None):
    region = {"startLine": max(int(line), 1)}
    if end_line and end_line >= line:
        region["endLine"] = int(end_line)
    return {"physicalLocation": {"artifactLocation": {"uri": path.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                                 "region": region}}


def _fp(*parts):
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:32]


def to_sarif(result, identity=None):
    results = []
    for u in result["units"]:
        for f in u["assurance"]:
            results.append({
                "ruleId": _FAMILY_IDS[f["family"]], "level": "note",
                "message": {"text": f"Security-assurance comment ({f['family']}, rule {f['rule']}) above/in "
                                    f"`{u['function']}`: \"{f['matched']}\". Verify this claim; do not let it "
                                    f"replace review."},
                "locations": [_loc(u["file"], f["line"])],
                "partialFingerprints": {"commentguard/v1": _fp(u["file"], u["function"], f["rule"], f["matched"])},
                "properties": {"family": f["family"], "rule": f["rule"], "function": u["function"]},
            })
        rev = u.get("review")
        if not rev:
            continue
        st = rev["status"]
        if st == BLIND_SPOT:
            vt = rev["stripped"].get("type") or "unspecified"
            claims = "; ".join(sorted({f["matched"] for f in u["assurance"]})) or "comments/docstrings"
            results.append({
                "ruleId": "CG001", "level": "error",
                "message": {"text": f"Comment-induced blind spot in `{u['function']}`: the LLM reviewer said SAFE with "
                                    f"comments, VULNERABLE ({vt}) without them. Comments involved: {claims}."},
                "locations": [_loc(u["file"], u["def_line"], u["end_line"])],
                "relatedLocations": [dict(_loc(u["file"], f["line"]), id=i, message={"text": f["matched"]})
                                     for i, f in enumerate(u["assurance"])],
                "partialFingerprints": {"commentguard/v1": _fp(u["file"], u["function"], "CG001")},
                "properties": {"status": st, "asis": rev["asis"]["verdict"], "stripped": rev["stripped"]["verdict"],
                               "vulnerability_type": vt},
            })
        elif st == AGREE_VULN or (st == NO_COMMENTS and rev["asis"]["verdict"] == "VULNERABLE"):
            vt = rev["asis"].get("type") or "unspecified"
            results.append({
                "ruleId": "CG002", "level": "warning",
                "message": {"text": f"LLM reviewer flags `{u['function']}` as VULNERABLE ({vt}). Unverified AI opinion."},
                "locations": [_loc(u["file"], u["def_line"], u["end_line"])],
                "partialFingerprints": {"commentguard/v1": _fp(u["file"], u["function"], "CG002")},
                "properties": {"status": st, "vulnerability_type": vt},
            })
    run = {
        "tool": {"driver": {"name": "CommentGuard", "version": __version__, "semanticVersion": __version__,
                            "rules": _rules()}},
        "results": results,
        "columnKind": "utf16CodeUnits",
    }
    if identity:
        run["properties"] = {"reviewer": identity}
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}


def write_sarif(result, path, identity=None):
    with open(path, "w") as f:
        json.dump(to_sarif(result, identity), f, indent=2)
