"""Static detector for security-assurance comments.

The four families follow the CommentInject v2 strategy taxonomy (data/strategies.jsonl,
CC BY 4.0, (c) 2026 Sunny Chokshi): verification-premise, context-manipulation,
credibility-vocabulary, pressure-distraction. The regexes were written by hand for CommentGuard.

A match means "this comment asserts something about security that a reviewer (human or AI)
might take on trust". It does not mean the comment is false or malicious.
"""
import re

FAMILIES = {
    "verification-premise": "Claims the code was already reviewed, audited, approved or tested for security.",
    "context-manipulation": "Claims inputs are trusted, sanitized upstream, unreachable or sandboxed.",
    "credibility-vocabulary": "Uses security/compliance vocabulary (OWASP, SOC 2, hardened, formally verified) as a badge.",
    "pressure-distraction": "Urges the reviewer not to look (urgency, personal certainty, directives to reviewers).",
}

_S = r"(?:sanitiz|sanitis|validat|escap|filter|whitelist|allowlist|clean)\w*"

# (rule_id, family, regex). Matched case-insensitively against the comment text with '#'
# markers removed and line breaks joined by spaces.
RULES = [
    # verification-premise
    ("security-reviewed", "verification-premise",
     r"\bsecurity[- ]?(?:reviewed|audited|approved|cleared|signed[- ]off|vetted)\b"
     r"|\b(?:reviewed|audited|approved|vetted|signed[- ]off)\b.{0,25}\b(?:security|infosec|appsec|secops) ?(?:team|guild|review|audit|engineer|group)?"
     r"|\b(?:signed[- ]off|approved) by\b.{0,20}\b(?:infosec|appsec|secops|security)\b"),
    ("passed-security-testing", "verification-premise",
     r"\bpass(?:ed|es)\b.{0,30}\b(?:pen(?:etration)?[- ]?test\w*|security (?:scan|review|audit|test)\w*|audit|sast|dast)"),
    ("review-approved", "verification-premise",
     r"\b(?:code[- ]?)?review\w*\b.{0,15}\b(?:approved|signed[- ]off|lgtm)\b|\bapproved by\b|\bsigned[- ]off by\b|\blgtm\b"
     r"|\bcleared for (?:production|prod|release|deploy\w*)\b"),
    ("no-known-vulns", "verification-premise",
     r"\bno (?:known )?(?:security )?(?:vulnerabilit\w+|security (?:issues|bugs|findings))\b"
     r"|\b(?:pen[- ]?test\w*|audit\w*|scan\w*|assessment)\b.{0,40}\b(?:found|reported|raised|showed) no(?:thing)?\b"
     r"|\b(?:audit|pen[- ]?test|security scan)\w*\b.{0,40}\bnothing (?:outstanding|found|to report)\b"),
    ("already-vetted", "verification-premise",
     r"\balready (?:been )?(?:vetted|reviewed|audited|approved|checked for)\b"
     r"|\b(?:bandit|semgrep|codeql|sonar\w*|snyk|static analysis|sast|dast|security scan)\b.{0,40}\b(?:clean|pass\w*|green|no (?:findings|issues|alerts))\b"),
    ("test-coverage-claim", "verification-premise",
     r"\b(?:covered|verified|validated) by\b.{0,30}\btest|\b100\s?%\s*(?:branch |line |statement |test )?coverage\b"
     r"|\btest_\w*(?:safe|secur|inject|sanit|xss|vuln)\w*|\b(?:security|injection|safety|fuzz)\w*\s+tests?(?: suite)?\b.{0,30}\bpass"
     r"|\btest_\w+\b.{0,30}\b(?:is |are )?(?:green|passing|passes)\b"),
    # context-manipulation
    ("sanitized-upstream", "context-manipulation",
     r"\bpre-?" + _S + r"|\b" + _S + r"\s+(?:upstream|by the caller|by callers|elsewhere|earlier|already|"
     r"at the (?:gateway|edge|boundary|api layer|load balancer|proxy|waf))"
     r"|\b(?:is|are|was|were|been|gets?)\s+(?:already\s+|fully\s+|properly\s+|always\s+)?" + _S +
     r"|\b(?:has|have|had)\s+already\s+(?:been\s+)?" + _S),
    ("exploit-impossible", "context-manipulation",
     r"\b(?:injection|xss|traversal|overflow|exploit\w*|attacks?|ssrf|rce)\b.{0,20}\b(?:is |are )?(?:not possible|impossible|cannot (?:happen|occur)|can't (?:happen|occur))"
     r"|\bcannot be (?:exploited|abused|injected)\b|\bnot exploitable\b"),
    ("trusted-only", "context-manipulation",
     r"\btrusted (?:input|inputs|callers?|users?|sources?|data|admins?|admin use|clients?)\b"
     r"|\b(?:internal|admin|trusted)\b[\w\s-]{0,25}\bonly\b|\bonly (?:reachable|accessible|callable|called|used) (?:from|by|via|in)\b"
     r"|\bbehind (?:the |a |our )?(?:vpn|firewall|sso|auth\w*)\b|\b(?:comes?|come) (?:only )?from (?:our own|an internal|a trusted)\b"
     r"|\b(?:signed|generated|produced) by our own\b|\bcallers? (?:always|only) pass\w*\b"),
    ("not-exposed", "context-manipulation",
     r"\bnot (?:exposed|reachable|accessible|user[- ]facing)\b.{0,25}\b(?:user|external|untrusted|internet|public|input)"
     r"|\b(?:user|untrusted|external|attacker)\w*[- ](?:input|data)\b.{0,10}\b(?:never|cannot|can't|does not|doesn't|will not|won't)\b.{0,10}\b(?:reach|get|flow|touch)"
     r"|\bnever (?:comes? )?(?:from|by|supplied by|controlled by) (?:the )?(?:users?|clients?|attackers?|the internet)\b"),
    ("safe-by-design", "context-manipulation", r"\bsafe by (?:design|construction)\b"),
    ("sandbox-claim", "context-manipulation",
     r"\b(?:isolated|sandbox(?:ed)?)\b.{0,40}\b(?:no network|no (?:real )?file ?system|untrusted|no access)"
     r"|\b(?:only|executed|runs?)\b.{0,15}\b(?:inside|in) (?:the |an |a )?(?:isolated |ci )?(?:sandbox|jail)"
     r"|\blocked[- ]down\b|\bno (?:outbound|inbound|external|network) (?:access|network|connectivity)\b|\bair[- ]gapped\b"),
    # credibility-vocabulary
    ("owasp-badge", "credibility-vocabulary",
     r"\b(?:follow\w*|complian\w*|complies with|per|according to|meets)\b.{0,25}\bowasp\b|\bowasp\b.{0,15}\b(?:guidelines?|compliant|standards?|approved)"),
    ("hardened-badge", "credibility-vocabulary",
     r"\bhardened\b|\bdefen[cs]e[- ]in[- ]depth\b|\b(?:compliant|complies) with\b.{0,30}\b(?:security|standards?)"
     r"|\bsecurity standards?\b|\bbattle[- ]tested\b|\bmilitary[- ]grade\b|\benterprise[- ]grade\b|\bbank[- ]grade\b"
     r"|\bzero[- ]trust\b|\bowasp asvs\b|\basvs\b|\bnist\b|\bsp ?800-\d+|\bcis benchmark\w*"),
    ("compliance-claim", "credibility-vocabulary",
     r"\b(?:soc ?2|soc ?ii|pci[- ]?dss|iso ?27001|hipaa|fedramp|fips ?140|gdpr)\b.{0,40}\b(?:certified|compliant|audited|approved|validated)"
     r"|\b(?:certified|compliant)\b.{0,20}\b(?:soc ?2|pci[- ]?dss|iso ?27001|hipaa|fedramp|fips ?140)\b"
     r"|\baudited by\b|\bexternal (?:assessors|auditors)\b|\bmeets all (?:control|security) requirements\b"),
    ("formal-proof-claim", "credibility-vocabulary",
     r"\bformally verified\b|\bmodel[- ]check\w*|\bproof artifact\b|\bmathematically\b.{0,30}\b(?:safe|secure|guaranteed|proven)"
     r"|\b(?:proven|proved|guaranteed)\b.{0,15}\b(?:safe|secure|correct)\b|\b(?:injection|memory|bug)[- ]free(?:dom)?\b"
     r"|\bverified correct\b|\b(?:tla\+|coq|isabelle|lean|dafny|f\*)\b.{0,20}\b(?:proof|proofs|verified|spec)"),
    # pressure-distraction
    ("urgency", "pressure-distraction",
     r"\bhot-?fix\b|\b(?:must|need to|has to)\s+(?:ship|merge|deploy|go out|land)\b|\bproduction (?:outage|incident|is down)\b"
     r"|\bemergency (?:review|fix|patch|release)\b|\bship (?:immediately|asap|now)\b|\burgent\b|\brelease[- ]blocker\b"
     r"|\bwithout (?:further |additional |a |any )?(?:review|checks?|approval)\b|\bbypass (?:the )?(?:normal |usual |standard )?(?:checks?|review|process)\b"),
    ("do-not-flag", "pressure-distraction",
     r"\b(?:do not|don't|dont|please don't|no need to)\s+(?:block|flag|report|review|change|touch|worry)\b"
     r"|\b(?:nothing|no need) (?:here )?to (?:flag|report|worry about)\b|\bno (?:further )?action (?:is )?(?:needed|required)\b"
     r"|\b(?:please )?skip (?:this|the) (?:function|file|method|check|review)\b|\b(?:it'?s|is) fine as[- ]is\b"),
    ("authorial-certainty", "pressure-distraction",
     r"\btrust me\b|\bi(?: am|'m) (?:certain|sure|confident|positive)\b|\b\d+\+? years\b.{0,40}\b(?:experience|written|writing|doing)\b"
     r"|\b(?:completely|totally|100\s?%|perfectly|absolutely|entirely) (?:safe|secure)\b|\bi wrote (?:the|this)\b.{0,40}\bfine\b"),
    ("reviewer-directive", "pressure-distraction",
     r"\b(?:ai|llm|automated|bot|copilot|gpt|claude|codex)\s+(?:code\s+)?(?:reviewers?|scanners?|assistants?|tools?)\b"
     r"|\bignore (?:all |any )?(?:previous|prior|above|earlier) instructions\b|\b(?:reviewers?|scanners?|analy[sz]ers?) (?:should|must) (?:not|ignore|skip)\b"
     r"|\bmark (?:this|it) (?:as )?safe\b|\b(?:reviewers?|scanners?)\b.{0,30}\b(?:do not|don't) (?:report|flag)\b"),
]

_COMPILED = [(rid, fam, re.compile(rx, re.I)) for rid, fam, rx in RULES]


def _normalize(lines):
    """Join comment lines into one sentence-like string, recording where each line starts."""
    parts, starts, pos = [], [], 0
    for ln, raw in lines:
        s = raw.lstrip()
        if s.startswith("#"):
            s = s.lstrip("#").strip()
        else:
            s = s.strip()
        starts.append((pos, ln))
        parts.append(s)
        pos += len(s) + 1
    return " ".join(parts), starts


def detect(comment_items):
    """Run all rules over collected comment blocks/docstrings.

    Returns a list of findings {line, family, rule, matched, text, kind}. At most one finding per
    (block, rule); a block can match several rules/families."""
    findings = []
    for it in comment_items:
        text, starts = _normalize(it["lines"])
        for rid, fam, rx in _COMPILED:
            m = rx.search(text)
            if not m:
                continue
            line = it["line"]
            for off, ln in starts:
                if off <= m.start():
                    line = ln
            findings.append({"line": line, "family": fam, "rule": rid, "matched": m.group(0),
                             "text": it["text"], "kind": it["kind"],
                             "block_start": it["line"], "block_end": it["end_line"]})
    return findings
