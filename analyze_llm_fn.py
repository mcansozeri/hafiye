#!/usr/bin/env python3
"""
Why does the LLM reject true secrets?  (free, local — no API calls)

Reads benchmark_results/llm_gpt-4.1-mini.jsonl + CredData meta and reports, for the
true secrets (GT=T) that the LLM marked as false positive:
  - category breakdown (vs. category breakdown of the T it kept)
  - most frequent words/phrases in the LLM 'reason' field
  - per-repo rejection rate (to spot obfuscated vs. raw repos)
  - a few short, anonymised examples for the paper
Writes benchmark_results/llm_fn_analysis.md
"""
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from run_benchmark import load_ground_truth, load_llm_cache, DEFAULT_META_DIR, DEFAULT_OUT_DIR, LLM_MODEL  # noqa

out = Path(DEFAULT_OUT_DIR)
llm = load_llm_cache(out / f"llm_{LLM_MODEL}.jsonl")
repos = sorted({v["repo"] for v in llm.values()})
gt = load_ground_truth(Path(DEFAULT_META_DIR), repos)

rejected, kept = [], []
for v in llm.values():
    lab = gt.get(v["repo"], {}).get(v["file"], {}).get(v["line"])
    if not lab or lab["label"] != "T":
        continue
    v = {**v, "category": lab["category"].split(":")[0]}
    (rejected if v["is_false_positive"] else kept).append(v)

md = [f"# Why the LLM rejects true secrets ({LLM_MODEL})\n",
      f"True secrets reaching the LLM: {len(rejected) + len(kept)}; rejected as false positive: {len(rejected)} "
      f"({len(rejected) / max(1, len(rejected) + len(kept)):.1%}).\n"]

# --- category breakdown
cr, ck = Counter(v["category"] for v in rejected), Counter(v["category"] for v in kept)
md.append("## Rejected true secrets by CredData category\n")
md.append("| Category | rejected | kept | rejection rate | share of all rejections |\n|---|---|---|---|---|")
for c, n in sorted(cr.items(), key=lambda x: -x[1]):
    tot = n + ck.get(c, 0)
    md.append(f"| {c} | {n} | {ck.get(c, 0)} | {n / tot:.1%} | {n / len(rejected):.1%} |")
low_risk = {"UUID", "Nonce", "Salt", "Key", "AWS Client ID", "Firebase Domain"}
lr = sum(n for c, n in cr.items() if c in low_risk)
md.append(f"\nRejections in low-exploitability categories ({', '.join(sorted(low_risk))}): {lr} / {len(rejected)} = {lr / max(1, len(rejected)):.1%}\n")

# --- reasons
md.append("## Most frequent phrases in the LLM 'reason' for rejected true secrets\n")
phrases = Counter()
pat = [("placeholder / example / dummy", r"placeholder|example|dummy|sample|fake|test"),
       ("configuration / metadata", r"configuration|config|metadata|setting|parameter"),
       ("identifier / UUID / id", r"identifier|uuid|\bid\b|guid"),
       ("public / non-sensitive", r"public|not sensitive|non-sensitive|no sensitive"),
       ("hash / checksum / salt", r"hash|checksum|salt|digest"),
       ("variable / reference, not a value", r"variable|reference|function|method|name"),
       ("URL / path / domain", r"url|path|domain|endpoint"),
       ("encoded / obfuscated", r"encoded|obfuscat|base64"),
       ("truncated / masked", r"truncat|mask|redact|\*\*\*")]
for v in rejected:
    r = v.get("reason", "").lower()
    for name, rx in pat:
        if re.search(rx, r):
            phrases[name] += 1
md.append("| Reason theme | count | share |\n|---|---|---|")
for name, n in phrases.most_common():
    md.append(f"| {name} | {n} | {n / len(rejected):.1%} |")

# --- per-repo rejection rate (obfuscation artefacts show up as bimodal rates)
md.append("\n## Per-repo rejection rate of true secrets (repos with ≥20 true secrets sent to LLM)\n")
per = defaultdict(lambda: [0, 0])
for v in rejected: per[v["repo"]][0] += 1
for v in kept: per[v["repo"]][1] += 1
rows = [(r, a, b, a / (a + b)) for r, (a, b) in per.items() if a + b >= 20]
rows.sort(key=lambda x: -x[3])
md.append("| repo | rejected | kept | rate |\n|---|---|---|---|")
for r, a, b, rate in rows[:15]:
    md.append(f"| {r} | {a} | {b} | {rate:.1%} |")
md.append("| … | | | |")
for r, a, b, rate in rows[-5:]:
    md.append(f"| {r} | {a} | {b} | {rate:.1%} |")
rates = [x[3] for x in rows]
if rates:
    md.append(f"\nRepos ≥20: {len(rows)}; median rate {sorted(rates)[len(rates) // 2]:.1%}; "
              f"repos with rate >60%: {sum(r > .6 for r in rates)}, <20%: {sum(r < .2 for r in rates)}\n")

# --- examples
md.append("## Examples (values shortened; CredData values are obfuscated where obfuscation ran)\n")
seen = set()
for v in rejected:
    c = v["category"]
    if c in seen: continue
    seen.add(c)
    ctx = re.sub(r"\s+", " ", v.get("context", ""))[:110]
    md.append(f"- **{c}** — `{ctx}` → *{v.get('reason', '')[:140]}*")
    if len(seen) >= 8: break

(out / "llm_fn_analysis.md").write_text("\n".join(md), encoding="utf-8")
print("\n".join(md))
