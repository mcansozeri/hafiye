#!/usr/bin/env python3
"""
Tables of the paper, computed from benchmark_results/ (no API calls).

Writes benchmark_results/paper_tables.md:
  T-A  Main results, all categories                      -> Tables 2 and 3
  T-B  Same, UUID category excluded                      -> Table 5
  T-C  Pre-filter-only baseline                          -> Table 2
  T-D  LLM-stage retention vs end-to-end recall
  T-E  Effect of the LLM per category (markup level)     -> Table 4
  T-F  Excluded files and unlabelled findings (incl. LLM cost estimate)
  T-G  Evaluation splits                                 -> Table 1
  T-H  Themes in the LLM explanations of rejected true secrets
  T-I  Threshold sweep on the validation split           -> Table 6, Figure 3
  T-J  Other numbers used in the text (UUID share, X-excluded precision, LLM tokens, confidence levels)

Usage (project root):  python paper_tables.py
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_benchmark import (DEFAULT_DATA_DIR, DEFAULT_META_DIR, DEFAULT_OUT_DIR, DEFAULT_THRESHOLD, LLM_MODEL,  # noqa
                           load_split, scanned_repos, primary_variant, load_scans, load_ground_truth,
                           load_llm_cache, llm_key, evaluate, predictions, merged_candidates)

# gpt-4.1-mini list price (USD per 1M tokens) used only for the cost estimate in T-F
PRICE_IN, PRICE_OUT = 0.40, 1.60

out = Path(DEFAULT_OUT_DIR)
data_dir = Path(DEFAULT_DATA_DIR)
meta_dir = Path(DEFAULT_META_DIR)
split = load_split(out)
test = scanned_repos(out, split["test"])
variant = primary_variant(out, test)
ds, cb = load_scans(out, test, variant)
ds_stock = load_scans(out, test, "stock")[0]
llm = load_llm_cache(out / f"llm_{LLM_MODEL}.jsonl")
info = json.loads((out / "llm_repos.json").read_text())
lrepos = [r for r in info["repos"] if r in test]
thr = info.get("threshold", DEFAULT_THRESHOLD)

md = ["# Paper tables\n",
      f"Test split: {len(test)} repositories; rule-based component = detect-secrets 1.5.0 ({variant}); "
      f"CodeBERT threshold {thr}; LLM {LLM_MODEL}. Counting unit everywhere = one CredData markup "
      "(a multi-line secret such as a PEM block counts once and is detected if any of its lines is reported).\n"]

HDR = "| Configuration | TP | FP | FN | TN | Precision | Recall | F1 | FPR | FNR |\n|---|---|---|---|---|---|---|---|---|---|"
def row(name, m):
    return (f"| {name} | {m['TP']} | {m['FP']} | {m['FN']} | {m['TN']} | {m['precision']:.3f} | {m['recall']:.3f} "
            f"| {m['f1']:.3f} | {m['FPR']:.3f} | {m['FNR']:.3f} |")

_load_gt_all = load_ground_truth
def load_ground_truth(meta_dir_, repos, exclude_x=False, exclude_categories=(), downloaded_only=True):
    """Evaluation universe = labelled rows in files that exist in the downloaded data.
    Rows in files that were not downloaded can be neither detected nor falsely reported,
    so counting them as TN/FN would bias FPR (down) and recall (down)."""
    g = _load_gt_all(meta_dir_, repos, exclude_x=exclude_x, exclude_categories=exclude_categories)
    if downloaded_only:
        g = {r: {f: v for f, v in files.items() if (data_dir / r / f).exists()} for r, files in g.items()}
    return g

def only_lines(d):          # helper: dict of sets
    return {r: set(v) for r, v in d.items()}

def configs(repos):
    """name -> prediction dict"""
    P = {}
    P["Rule-based (stock)"] = {r: set(ds_stock[r].keys()) for r in repos}
    P["Rule-based"] = predictions(ds, cb, repos, "regex", thr)
    P["Pre-filter only (all pre-filtered assignment lines)"] = predictions(ds, cb, repos, "codebert", 0.0)
    P[f"CodeBERT @{thr}"] = predictions(ds, cb, repos, "codebert", thr)
    P["Rule-based ∪ pre-filter only"] = predictions(ds, cb, repos, "union", 0.0)
    P[f"Union (rule-based ∪ CodeBERT @{thr})"] = predictions(ds, cb, repos, "union", thr)
    P["Rule-based + LLM"] = predictions(ds, cb, repos, "regex", thr, llm)
    P[f"CodeBERT @{thr} + LLM"] = predictions(ds, cb, repos, "codebert", thr, llm)
    P["Union + LLM (full pipeline)"] = predictions(ds, cb, repos, "union", thr, llm)
    return P

def block(title, excl):
    gt = load_ground_truth(meta_dir, lrepos, exclude_categories=excl)
    P = configs(lrepos)
    M = {k: evaluate(gt, lrepos, v) for k, v in P.items()}
    md.append(f"## {title}\n")
    md.append(HDR)
    for k in ["Rule-based (stock)", "Rule-based", f"CodeBERT @{thr}", f"Union (rule-based ∪ CodeBERT @{thr})",
              "Rule-based + LLM", f"CodeBERT @{thr} + LLM", "Union + LLM (full pipeline)"]:
        md.append(row(k, M[k]))
    md.append("")
    return gt, P, M

# ---------------- T-A / T-B
gtA, PA, MA = block("T-A. Main results, all categories (UUID included) — PRIMARY", ())
gtB, PB, MB = block("T-B. UUID category excluded — SUPPLEMENTARY", ("UUID",))

# ---------------- T-C pre-filter baseline
md.append("## T-C. Pre-filter-only baseline (all categories)\n")
md.append("The pre-filter-only configuration reports every line that passes the heuristic filters of the semantic module "
          "(assignment operator, quoted or numeric value, no comment/import/null), without any CodeBERT similarity test.\n")
md.append(HDR)
for k in ["Pre-filter only (all pre-filtered assignment lines)", f"CodeBERT @{thr}",
          "Rule-based ∪ pre-filter only", f"Union (rule-based ∪ CodeBERT @{thr})"]:
    md.append(row(k, MA[k]))
# completeness check: were all pre-filtered lines stored (score >= floor)?
stored = analysed = 0
for r in lrepos:
    p = out / "codebert" / f"{r}.jsonl"
    with open(p, encoding="utf-8") as fh:
        head = json.loads(fh.readline())
        analysed += head.get("lines_analyzed", 0)
        stored += sum(1 for _ in fh)
pf = sum(len(v) for v in PA["Pre-filter only (all pre-filtered assignment lines)"].values())
cbn = sum(len(v) for v in PA[f"CodeBERT @{thr}"].values())
md.append(f"\nPre-filtered lines analysed: {analysed:,}; stored with similarity ≥ 0.60: {stored:,} "
          f"(coverage {stored / max(1, analysed):.2%}). Lines flagged: pre-filter only {pf:,}, CodeBERT @{thr} {cbn:,} "
          f"(CodeBERT removes {pf - cbn:,} lines = {(pf - cbn) / max(1, pf):.2%}).\n")

# ---------------- T-D retention vs end-to-end recall
md.append("## T-D. LLM-stage retention vs end-to-end recall\n")
md.append("LLM-stage retention = true secrets kept by the LLM / true secrets among the candidates sent to the LLM. "
          "End-to-end recall = true secrets reported by the full pipeline / all true secrets in the test split.\n")
md.append("| Setting | True secrets (all) | Detected by candidates | Kept after LLM | Candidate recall | LLM-stage retention | End-to-end recall |\n|---|---|---|---|---|---|---|")
for name, M in (("All categories", MA), ("UUID excluded", MB)):
    a = M[f"Union (rule-based ∪ CodeBERT @{thr})"]; b = M["Union + LLM (full pipeline)"]
    tot = a["TP"] + a["FN"]
    md.append(f"| {name} | {tot:,} | {a['TP']:,} | {b['TP']:,} | {a['TP'] / tot:.3f} | {b['TP'] / max(1, a['TP']):.3f} | {b['TP'] / tot:.3f} |")
fp_a, fp_b = MA[f"Union (rule-based ∪ CodeBERT @{thr})"]["FP"], MA["Union + LLM (full pipeline)"]["FP"]
md.append(f"\nFalse positives removed by the LLM (all categories): {fp_a - fp_b:,} of {fp_a:,} ({(fp_a - fp_b) / max(1, fp_a):.1%}).\n")

# ---------------- T-E per category, markup level
md.append("## T-E. Effect of the LLM per category (all categories, markup level — same unit as T-A)\n")
md.append("| Category | True secrets | Detected before LLM | Kept after LLM | Rejected by LLM | LLM-stage retention | End-to-end recall |\n|---|---|---|---|---|---|---|")
pa = MA[f"Union (rule-based ∪ CodeBERT @{thr})"]["per_category_recall"]
pb = MA["Union + LLM (full pipeline)"]["per_category_recall"]
rows = []
for c, v in pa.items():
    kept = pb.get(c, {}).get("tp", 0)
    rows.append((v["total"], c, v["tp"], kept))
rows.sort(reverse=True)
sumT = sumD = sumK = 0
for total, c, det, kept in rows:
    sumT += total; sumD += det; sumK += kept
    if total < 20:
        continue
    md.append(f"| {c} | {total:,} | {det:,} | {kept:,} | {det - kept:,} | {kept / det if det else 0:.3f} | {kept / total:.3f} |")
md.append(f"| **All categories** | {sumT:,} | {sumD:,} | {sumK:,} | {sumD - sumK:,} | {sumK / max(1, sumD):.3f} | {sumK / max(1, sumT):.3f} |")
low = {"UUID", "Nonce", "Salt", "AWS Client ID", "Firebase Domain"}
rej = {c: det - kept for _, c, det, kept in rows}
lr = sum(v for c, v in rej.items() if c in low)
md.append(f"\nRejections in low-exploitability categories ({', '.join(sorted(low))}): {lr:,} of {sumD - sumK:,} "
          f"({lr / max(1, sumD - sumK):.1%}).")
hv = {"Password", "PEM Private Key", "API", "Secret", "Auth"}
hd = sum(det for _, c, det, kept in rows if c in hv); hk = sum(kept for _, c, det, kept in rows if c in hv)
md.append(f"High-value categories ({', '.join(sorted(hv))}): LLM-stage retention {hk:,}/{hd:,} = {hk / max(1, hd):.1%}.\n")

# ---------------- T-F excluded files and unlabelled findings
md.append("## T-F. Excluded files and unlabelled findings\n")
# (1) labelled rows whose file is not in the downloaded data (file filter / missing repos)
lab_all = Counter(); lab_missing = Counter()
import csv
for r in split["test"]:
    p = meta_dir / f"{r}.csv"
    if not p.exists():
        continue
    with open(p, encoding="utf-8") as f:
        for row_ in csv.DictReader(f):
            g = row_["GroundTruth"].strip()
            fp = row_["FilePath"]
            fp = fp[len("data/"):] if fp.startswith("data/") else fp
            lab_all[g] += 1
            if not (data_dir / fp).exists():
                lab_missing[g] += 1
md.append("| Label | Labelled rows in test repositories | Rows in files not downloaded | Share excluded |\n|---|---|---|---|")
for g in ("T", "F", "X"):
    md.append(f"| {g} | {lab_all[g]:,} | {lab_missing[g]:,} | {lab_missing[g] / max(1, lab_all[g]):.1%} |")
md.append("\nAll tables above use the downloaded-files universe: rows in files that were not downloaded are excluded "
          "(they can be neither detected nor falsely reported). The table below compares this with counting them as TN/FN. "
          "Comparison (all categories):\n")
gt_old = load_ground_truth(meta_dir, lrepos, downloaded_only=False)
md.append("| Configuration | FPR (rows of non-downloaded files counted as TN) | FPR (downloaded files only) | Recall (old) | Recall (downloaded only) | Precision (both) |\n|---|---|---|---|---|---|")
for k in ["Rule-based", f"CodeBERT @{thr}", f"Union (rule-based ∪ CodeBERT @{thr})", "Union + LLM (full pipeline)"]:
    mo = evaluate(gt_old, lrepos, PA[k]); mn = MA[k]
    md.append(f"| {k} | {mo['FPR']:.3f} | {mn['FPR']:.3f} | {mo['recall']:.3f} | {mn['recall']:.3f} | {mn['precision']:.3f} |")
md.append("")
# (2) unlabelled findings
md.append("| Configuration | Reported lines on labelled rows | Reported lines without a CredData label |\n|---|---|---|")
for k in ["Rule-based", f"CodeBERT @{thr}", f"Union (rule-based ∪ CodeBERT @{thr})"]:
    m = MA[k]
    md.append(f"| {k} | {m['TP'] + m['FP']:,} | {m['unlabeled_reported']:,} |")
md.append("\nUnlabelled findings are not counted in any metric (CredData convention) and were not sent to the LLM in this evaluation.\n")
# (3) cost if every candidate (labelled + unlabelled) were sent to the LLM
calls = len(llm)
tin = sum(v.get("prompt_tokens", 0) for v in llm.values()); tout = sum(v.get("completion_tokens", 0) for v in llm.values())
all_cands = sum(len(merged_candidates(ds[r], cb[r], thr)) for r in lrepos)
avg_in, avg_out = tin / max(1, calls), tout / max(1, calls)
cost_done = tin / 1e6 * PRICE_IN + tout / 1e6 * PRICE_OUT
cost_all = all_cands * (avg_in / 1e6 * PRICE_IN + avg_out / 1e6 * PRICE_OUT)
md.append(f"\nLLM calls made (labelled candidates only): {calls:,}; tokens {tin + tout:,} (avg {avg_in:.0f} in / {avg_out:.0f} out); "
          f"cost ≈ ${cost_done:.2f}. If every candidate in the test repositories were verified (labelled + unlabelled): "
          f"{all_cands:,} calls, ≈ {all_cands * (avg_in + avg_out) / 1e6:.1f} M tokens, ≈ ${cost_all:,.0f} "
          f"(gpt-4.1-mini list price ${PRICE_IN}/M input, ${PRICE_OUT}/M output).\n")


# ---------------- T-G Table 1 counts in the same (markup) unit
import re as _re
def markup_counts(gt, repos):
    c = Counter()
    for r in repos:
        seen = {}
        for f, lines in gt.get(r, {}).items():
            for ln, d in lines.items():
                key = (f, d["line_start"])
                if key not in seen or d["label"] == "T":
                    seen[key] = d["label"]
        c.update(seen.values())
    return c
val = scanned_repos(out, split["validation"])
md.append("## T-G. Evaluation splits, markup unit (for Table 1)\n")
md.append("| Split | Setting | Repos | True (T) | False (F) | Uncertain (X) |\n|---|---|---|---|---|---|")
for sname, reps in (("Validation", val), ("Test", test)):
    for setting, excl in (("All categories", ()), ("UUID excluded", ("UUID",))):
        g = load_ground_truth(meta_dir, reps, exclude_categories=excl)
        c = markup_counts(g, reps)
        md.append(f"| {sname} | {setting} | {len(reps)} | {c['T']:,} | {c['F']:,} | {c['X']:,} |")
md.append("")

# ---------------- T-H reasons for rejected true secrets, markup level
before = PA[f"Union (rule-based ∪ CodeBERT @{thr})"]; after = PA["Union + LLM (full pipeline)"]
themes = [("configuration / metadata", r"configuration|config|metadata|setting|parameter"),
          ("identifier / UUID / id", r"identifier|uuid|\bid\b|guid"),
          ("variable / reference, not a value", r"variable|reference|function|method|name"),
          ("public / non-sensitive", r"public|not sensitive|non-sensitive|no sensitive"),
          ("placeholder / example / dummy", r"placeholder|example|dummy|sample|fake|test")]
cnt = Counter(); nrej = 0
for r in lrepos:
    g = gtA.get(r, {})
    marks = defaultdict(set)
    for f, lines in g.items():
        for ln, d in lines.items():
            if d["label"] == "T":
                marks[(f, d["line_start"])].add(ln)
    for (f, ls), lines in marks.items():
        det = any((f, ln) in before[r] for ln in lines)
        kept = any((f, ln) in after[r] for ln in lines)
        if det and not kept:
            nrej += 1
            reasons = " ".join(llm.get(llm_key(r, f, ln), {}).get("reason", "") for ln in lines).lower()
            for name, rx in themes:
                if _re.search(rx, reasons):
                    cnt[name] += 1
md.append(f"## T-H. Themes in the LLM explanation of rejected true secrets (markup level, n = {nrej:,})\n")
md.append("| Theme | Rejected true secrets | Share |\n|---|---|---|")
for name, _ in themes:
    md.append(f"| {name} | {cnt[name]:,} | {cnt[name] / max(1, nrej):.1%} |")
md.append("")

# ---------------- T-I threshold sweep on the validation split (same universe as T-A) + Figure 3
from run_benchmark import SWEEP
import csv as _csv
dsv, cbv = load_scans(out, val, variant)
sims = sorted(v[0] for r in val for v in cbv[r].values())
md.append("## T-I. Threshold sweep, validation split (downloaded-files universe; Table 6 and Figure 3)\n")
if sims:
    q = lambda x: sims[min(len(sims) - 1, int(x * len(sims)))]
    md.append(f"Pre-filtered lines: {len(sims):,}; max-similarity min {sims[0]:.3f}, median {q(.5):.3f}, "
              f"share >= 0.85: {sum(v >= .85 for v in sims) / len(sims):.1%}.\n")
for tag, excl in (("", ()), ("_noUUID", ("UUID",))):
    gv = load_ground_truth(meta_dir, val, exclude_categories=excl)
    rows_ = []
    for t in SWEEP:
        mc = evaluate(gv, val, predictions(dsv, cbv, val, "codebert", t))
        mu = evaluate(gv, val, predictions(dsv, cbv, val, "union", t))
        rows_.append({"threshold": t, "cb_P": mc["precision"], "cb_R": mc["recall"], "cb_F1": mc["f1"],
                      "un_P": mu["precision"], "un_R": mu["recall"], "un_F1": mu["f1"]})
    with open(out / f"sweep_validation{tag}.csv", "w", newline="") as fh:
        w = _csv.DictWriter(fh, fieldnames=list(rows_[0])); w.writeheader(); w.writerows(rows_)
    best = max(rows_, key=lambda x: (round(x["un_F1"], 6), x["threshold"]))
    bestc = max(rows_, key=lambda x: (round(x["cb_F1"], 6), x["threshold"]))
    md.append(f"### {'All categories' if not tag else 'UUID excluded'}\n")
    md.append("| thr | CB P | CB R | CB F1 | Union P | Union R | Union F1 |\n|---|---|---|---|---|---|---|")
    for r_ in rows_:
        if round(r_["threshold"] * 100) % 5 == 0 or r_["threshold"] in (best["threshold"], bestc["threshold"]):
            md.append(f"| {r_['threshold']:.2f} | {r_['cb_P']:.3f} | {r_['cb_R']:.3f} | {r_['cb_F1']:.3f} | {r_['un_P']:.3f} | {r_['un_R']:.3f} | {r_['un_F1']:.3f} |")
    md.append(f"\nBest F1: CodeBERT-only at {bestc['threshold']:.2f} ({bestc['cb_F1']:.3f}); union at {best['threshold']:.2f} ({best['un_F1']:.3f}).\n")
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        xs = [r_["threshold"] for r_ in rows_]
        fig, ax = plt.subplots(figsize=(6, 3.5))
        for k, lab in (("cb_P", "Precision"), ("cb_R", "Recall"), ("cb_F1", "F1")):
            ax.plot(xs, [r_[k] for r_ in rows_], label=lab)
        ax.axvline(DEFAULT_THRESHOLD, ls="--", c="gray", lw=0.8); ax.axvline(bestc["threshold"], ls=":", c="black", lw=0.8)
        ax.set_xlabel("cosine similarity threshold"); ax.set_ylabel("score"); ax.set_title("CodeBERT-only, validation split")
        ax.legend(); fig.tight_layout(); fig.savefig(out / f"sweep_validation{tag}.png", dpi=200)
    except Exception as e:
        md.append(f"(plot skipped: {e})")

# ---------------- T-J other numbers used in the text
md.append("## T-J. Other numbers used in the text\n")
n_meta = len(list(meta_dir.glob("*.csv")))
n_data = len([d for d in data_dir.iterdir() if d.is_dir()]) if data_dir.is_dir() else 0
md.append(f"- Repositories: {n_data} downloaded, {n_meta} with CredData labels (Dataset paragraph).")
ca = markup_counts(gtA, lrepos)
gt_uuid = load_ground_truth(meta_dir, lrepos)
cu = Counter()
for r in lrepos:
    for f, lines in gt_uuid.get(r, {}).items():
        for ln, d in lines.items():
            if d["line_start"] == ln and d["label"] == "T" and d["category"].split(":")[0] == "UUID":
                cu["T"] += 1
md.append(f"- UUID true secrets in the test split: {cu['T']:,} of {ca['T']:,} ({cu['T'] / max(1, ca['T']):.1%}) (UUID paragraph).")
gt_nox = load_ground_truth(meta_dir, lrepos, exclude_x=True)
m_nox = evaluate(gt_nox, lrepos, PA["Union + LLM (full pipeline)"])
m_x = MA["Union + LLM (full pipeline)"]
md.append(f"- Full pipeline with X rows excluded: precision {m_x['precision']:.3f} -> {m_nox['precision']:.3f}, "
          f"recall {m_x['recall']:.3f} -> {m_nox['recall']:.3f} (Threats to validity).")
md.append(f"- LLM calls: {calls:,}; tokens: {tin + tout:,} ({(tin + tout) / 1e6:.2f} M); cost ≈ ${cost_done:.2f} (Metrics paragraph).\n")
# confidence returned by the LLM, counted per verified line (the LLM is queried per line)
gt_lines = _load_gt_all(meta_dir, lrepos)
conf = Counter(); conf_total = Counter()
for v in llm.values():
    if v.get("repo") not in lrepos:
        continue
    lab = gt_lines.get(v["repo"], {}).get(v["file"], {}).get(v["line"], {}).get("label", "unlabeled")
    conf_total[v["confidence"]] += 1
    conf[(v["confidence"], "FP" if v["is_false_positive"] else "TP", lab)] += 1
md.append("Confidence level returned by the LLM (per verified line; Further observation: confidence level)\n")
md.append(f"Answers: high {conf_total['high']:,}, medium {conf_total['medium']:,}, low {conf_total['low']:,}.\n")
md.append("| LLM says | confidence | GT=T | GT=F | GT=X | unlabelled |\n|---|---|---|---|---|---|")
for says in ("TP", "FP"):
    for c_ in ("high", "medium", "low"):
        md.append(f"| {'secret' if says == 'TP' else 'false positive'} | {c_} | "
                  + " | ".join(f"{conf[(c_, says, l)]:,}" for l in ("T", "F", "X", "unlabeled")) + " |")
md.append("")

(out / "paper_tables.md").write_text("\n".join(md), encoding="utf-8")
print("\n".join(md))
print(f"\n[written] {out / 'paper_tables.md'}")
