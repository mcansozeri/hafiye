#!/usr/bin/env python3
"""
CredData benchmark for the hybrid secret scanner
(detect-secrets [rule-based] + CodeBERT [vector-based] + LLM verification).

Covers:
  1. Precision / Recall / F1 / FPR / FNR against CredData ground truth
  2. Ablation: rule-based, CodeBERT, union, and each +LLM
  3. Threshold sweep for CodeBERT on a validation split, evaluated on a held-out test split
  4. LLM verification on repositories not used for prompt development or threshold tuning

Usage (run from the project root, same venv you used for secret_scanner_main.py):

  python run_benchmark.py check                  # sanity checks (detect-secrets patch, torch, data)
  python run_benchmark.py split                  # repo-level validation/test split -> benchmark_results/split.json
  python run_benchmark.py scan                   # detect-secrets + CodeBERT over all repos (resumable)
  python run_benchmark.py llm --llm-repos 40     # LLM verification on a subset of TEST repos (resumable)
  python run_benchmark.py eval                   # metrics, ablation, threshold sweep -> benchmark_results/results.md

All stages are idempotent; re-running skips finished work.
"""
import argparse
import ast
import csv
import hashlib
import io
import json
import os
import random
import re
import subprocess
import sys
import time
from collections import defaultdict, Counter
from pathlib import Path

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

# --------------------------------------------------------------------------- #
# Defaults (relative to project root)
# --------------------------------------------------------------------------- #
DEFAULT_DATA_DIR = "benchmark/CredData/data"
DEFAULT_META_DIR = "benchmark/meta"
DEFAULT_OUT_DIR = "benchmark_results"
# CredData labels are pinned to the version used in the paper (see benchmark.py)
META_COMMIT = "c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d"
META_RAW_URL = "https://raw.githubusercontent.com/Samsung/CredData/" + META_COMMIT + "/meta/{repo}.csv"
UPGRADE_KEYWORD = "upgrade/tools/detect-secrets/detect_secrets/plugins/keyword.py"
UPGRADE_HEURISTIC = "upgrade/tools/detect-secrets/detect_secrets/filters/heuristic.py"
PATCHED_DIR = "tools/detect-secrets-patched"       # built by setup_patched_tools.py
DS_VARIANTS = {"stock": "detect_secrets", "patched": "detect_secrets_patched"}   # variant -> results subdir

CODEBERT_MODEL = os.environ.get("CODEBERT_MODEL", "microsoft/codebert-base")
SIM_FLOOR = 0.60          # store CodeBERT scores >= this so the sweep can go down to 0.60
SWEEP = [round(0.60 + 0.01 * i, 2) for i in range(0, 36)]   # 0.60 .. 0.95
DEFAULT_THRESHOLD = 0.85
LLM_MODEL = "gpt-4.1-mini"
LLM_TEMPERATURE = 0.3

# Exact prompt from secret_scanner_main.py (context_lines = 0 -> only the line itself)
PROMPT_TEMPLATE = """You are a senior security expert analyzing potential secrets in source code.

CODE CONTEXT:
The following content is raw source code.
It is NOT JSON and may contain syntax that is invalid in JSON.
Do NOT attempt to parse it as JSON.
Analyze it only as code text.

{context}

TASK:
Determine whether the detected item represents a real secret/credential that should be flagged, or a false positive.

MANDATORY DECISION RULES:
- A secret MUST contain sensitive secret material (e.g. tokens, passwords, keys).
- Configuration or metadata values are NOT secrets.
- Numeric values alone (e.g. lengths, sizes, iteration counts) are NEVER secrets.
- Fields describing cryptographic parameters are NOT secrets, including but not limited to:
  keyLength, keySize, saltLength, iterations, rounds, costFactor, algorithm, cipher, hash.

SEMANTIC CONTEXT RULES:
- Do NOT flag items that describe HOW a secret is generated or used.
- ONLY flag items that contain the secret value itself.

OBFUSCATION & ENTROPY:
- Entropy analysis applies ONLY if an actual value is present.
- High entropy heuristics MUST NOT be applied to numeric or configuration-only fields.

QUESTION:
Is this a real secret/credential that should be flagged, or is it a false positive?

Respond in JSON format:
{{
  "is_false_positive": true/false,
  "confidence": "high/medium/low",
  "reason": "Brief explanation"
}}"""


def log(msg):
    print(msg, flush=True)


# --------------------------------------------------------------------------- #
# Ground truth
# --------------------------------------------------------------------------- #
def ensure_meta(meta_dir: Path, repos):
    """Download meta/<repo>.csv from CredData GitHub if missing."""
    meta_dir.mkdir(parents=True, exist_ok=True)
    missing = [r for r in repos if not (meta_dir / f"{r}.csv").exists()]
    if not missing:
        return
    import requests
    log(f"[meta] downloading {len(missing)} meta files ...")
    for r in missing:
        url = META_RAW_URL.format(repo=r)
        resp = requests.get(url, timeout=60)
        if resp.status_code != 200:
            log(f"[meta] WARNING: {r}.csv not found upstream ({resp.status_code}); repo will be skipped")
            continue
        (meta_dir / f"{r}.csv").write_text(resp.text, encoding="utf-8")


def load_ground_truth(meta_dir: Path, repos, exclude_x=False, exclude_categories=()):
    """
    Returns:
      gt[repo][relpath][line] = dict(label='T'|'F'|'X', category=..., row_id=...)
      relpath is relative to the repo folder, e.g. 'sample/1d02852d.c'
    Multi-line markup (LineStart..LineEnd, e.g. PEM keys) expands to every line in the range.
    """
    gt = {}
    for repo in repos:
        p = meta_dir / f"{repo}.csv"
        if not p.exists():
            continue
        per_file = defaultdict(dict)
        with open(p, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                label = row["GroundTruth"].strip()
                if label not in ("T", "F", "X"):
                    continue
                if exclude_x and label == "X":
                    continue
                if exclude_categories and row.get("Category", "").split(":")[0] in exclude_categories:
                    continue
                fp = row["FilePath"]
                if fp.startswith("data/"):
                    fp = fp[len("data/"):]
                if fp.startswith(repo + "/"):          # make it relative to the repo folder
                    fp = fp[len(repo) + 1:]
                ls, le = int(row["LineStart"]), int(row["LineEnd"])
                for ln in range(ls, le + 1):
                    # if the same line has several markups, T wins (CredData convention)
                    prev = per_file[fp].get(ln)
                    if prev and prev["label"] == "T":
                        continue
                    per_file[fp][ln] = {"label": label, "category": row.get("Category", ""),
                                        "row_id": row.get("Id", ""), "line_start": ls}
        gt[repo] = dict(per_file)
    return gt


def gt_counts(gt, repos):
    t = f = x = 0
    for r in repos:
        for fp, lines in gt.get(r, {}).items():
            for ln, d in lines.items():
                if d["line_start"] != ln:      # count multi-line markups once
                    continue
                if d["label"] == "T":
                    t += 1
                elif d["label"] == "F":
                    f += 1
                else:
                    x += 1
    return t, f, x


# --------------------------------------------------------------------------- #
# Stage: check
# --------------------------------------------------------------------------- #
def stage_check(a):
    ok = True
    data_dir = Path(a.data_dir)
    log(f"[check] data dir: {data_dir.resolve()}")
    if not data_dir.is_dir():
        log("  !! data dir not found"); ok = False
    else:
        repos = sorted(d.name for d in data_dir.iterdir() if d.is_dir())
        log(f"  repos found: {len(repos)}")

    for p in (UPGRADE_KEYWORD, UPGRADE_HEURISTIC):
        log(f"[check] {p}: {'ok' if Path(p).exists() else 'MISSING'}")
        ok &= Path(p).exists()

    r = subprocess.run([sys.executable, "-m", "detect_secrets", "--version"], capture_output=True, text=True)
    log(f"[check] detect_secrets --version -> rc={r.returncode} {r.stdout.strip() or r.stderr.strip()[:200]}")
    ok &= r.returncode == 0

    r = subprocess.run([sys.executable, "-c", "import secret_keeper; print('secret_keeper importable')"], capture_output=True, text=True)
    log(f"[check] secret_keeper package (imported by your keyword.py): {r.stdout.strip() or 'not installed'}")
    r = subprocess.run([sys.executable, "-c",
                        "import detect_secrets.filters.heuristic as h;"
                        "print('patched' if hasattr(h,'is_language_specific_string') else 'UNPATCHED')"],
                       capture_output=True, text=True)
    log(f"[check] venv detect_secrets heuristic filter: {r.stdout.strip() or r.stderr.strip()[:200]}  (stock is expected here)")
    if patched_available():
        r = subprocess.run([sys.executable, "-c", "import detect_secrets.filters.heuristic as h;print('ok' if hasattr(h,'is_language_specific_string') else 'broken')"],
                           capture_output=True, text=True, env=patched_env())
        log(f"[check] {PATCHED_DIR}: {r.stdout.strip() or r.stderr.strip()[-200:]} -> scan will run BOTH stock and patched detect-secrets")
        ok &= "ok" in r.stdout
    else:
        log(f"[check] {PATCHED_DIR} not found -> scan will run stock detect-secrets only (run setup_patched_tools.py to add the patched variant)")

    try:
        import torch, transformers  # noqa
        dev = "cuda" if torch.cuda.is_available() else ("mps" if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available() else "cpu")
        log(f"[check] torch {torch.__version__}, transformers {transformers.__version__}, device={dev}")
    except Exception as e:
        log(f"  !! torch/transformers import failed: {e}"); ok = False

    try:
        import openai  # noqa
        log("[check] openai sdk: ok")
    except Exception:
        log("[check] openai sdk missing (only needed for the 'llm' stage): pip install openai")

    log("[check] RESULT: " + ("OK" if ok else "PROBLEMS FOUND"))


# --------------------------------------------------------------------------- #
# Stage: split
# --------------------------------------------------------------------------- #
def stage_split(a):
    data_dir, out = Path(a.data_dir), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    repos = sorted(d.name for d in data_dir.iterdir() if d.is_dir())
    ensure_meta(Path(a.meta_dir), repos)
    repos = [r for r in repos if (Path(a.meta_dir) / f"{r}.csv").exists()]
    rng = random.Random(a.seed)
    rng.shuffle(repos)
    n_val = max(1, int(round(len(repos) * a.val_frac)))
    split = {"seed": a.seed, "val_frac": a.val_frac,
             "validation": sorted(repos[:n_val]), "test": sorted(repos[n_val:])}
    gt = load_ground_truth(Path(a.meta_dir), repos)
    for k in ("validation", "test"):
        t, f, x = gt_counts(gt, split[k])
        split[f"{k}_counts"] = {"repos": len(split[k]), "T": t, "F": f, "X": x}
        log(f"[split] {k}: {len(split[k])} repos, T={t} F={f} X={x}")
    (out / "split.json").write_text(json.dumps(split, indent=2))
    log(f"[split] written {out/'split.json'}")


def load_split(out: Path):
    p = out / "split.json"
    if not p.exists():
        sys.exit("split.json not found — run `split` first")
    return json.loads(p.read_text())


# --------------------------------------------------------------------------- #
# Stage: scan  (detect-secrets + CodeBERT)
# --------------------------------------------------------------------------- #
def run_detect_secrets(repo_dir: Path, out_file: Path, env=None):
    if out_file.exists():
        return
    # detect-secrets silently ignores paths outside the current working directory -> always pass a relative path
    rel_dir = os.path.relpath(repo_dir, Path.cwd())
    if rel_dir.startswith(".."):
        sys.exit(f"data dir must be inside the project root (got {repo_dir})")
    cmd = [sys.executable, "-m", "detect_secrets", "scan", "--all-files", rel_dir]
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    findings = []
    if r.stdout.strip():
        try:
            data = json.loads(r.stdout)
        except json.JSONDecodeError:
            log(f"  [ds] JSON parse error for {repo_dir.name}: {r.stdout[:200]}")
            data = {}
        repo_abs = repo_dir.resolve()
        for fpath, secrets in data.get("results", {}).items():
            p = Path(fpath)
            try:
                rel = str(p.resolve().relative_to(repo_abs)).replace("\\", "/")
            except ValueError:
                # fall back: strip everything up to and including the repo folder name
                parts = fpath.replace("\\", "/").split("/")
                rel = "/".join(parts[parts.index(repo_dir.name) + 1:]) if repo_dir.name in parts else p.name
            for s in secrets:
                findings.append({"file": rel, "line": int(s.get("line_number", 0)), "type": s.get("type", "")})
    else:
        log(f"  [ds] no output for {repo_dir.name}: {r.stderr[:200]}")
    out_file.write_text(json.dumps({"repo": repo_dir.name, "findings": findings}, indent=1))


def patched_available():
    return Path(PATCHED_DIR, "detect_secrets", "__init__.py").exists()


def patched_env():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(PATCHED_DIR).resolve()) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return env


def load_denylist_keywords():
    """Mirror of SecretScanner.load_denylist_from_keyword_plugin()."""
    content = Path(UPGRADE_KEYWORD).read_text(encoding="utf-8")
    patterns = set()
    for name in ("DENYLIST", "DENYLIST2"):
        m = re.search(name + r"\s*=\s*\((.*?)\)", content, re.DOTALL)
        if m:
            patterns.update(re.findall(r"'([^']+)'", m.group(1)))
    cleaned = []
    for p in patterns:
        c = p.replace("_?", "_").replace("?", "")
        cleaned.append(p)
        if c != p:
            cleaned.append(c)
    return sorted(set(cleaned))


def load_ignored_extensions():
    """Mirror of SecretScanner.load_ignorelist_from_heuristic_filter()."""
    tree = ast.parse(Path(UPGRADE_HEURISTIC).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "IGNORED_FILE_EXTENSIONS" for t in node.targets):
            return list(ast.literal_eval(node.value.args[0]))
    return []


ASSIGN_OPS = ["=", ":", "=>", "<-", ":="]
SKIP_PREFIXES = ("#", "//", "/*", "*", "<!--", "import ", "from ", "using ")
NULLISH = {"null", "undefined", "none", "nil", "nan", "false", "true"}


def candidate_line(line: str):
    """Same pre-filters as run_codebert_scan(); returns stripped line or None."""
    s = line.strip()
    if not s or s.startswith(SKIP_PREFIXES):
        return None
    if not any(op in line for op in ASSIGN_OPS):
        return None
    value = None
    for op in ASSIGN_OPS:
        if op in line:
            parts = line.split(op, 1)
            if len(parts) > 1:
                value = parts[1].strip()
                break
    if not value:
        return None
    sv = value.strip("\"'` \t\n\r;,")
    if not sv or sv.lower() in NULLISH:
        return None
    has_quotes = any(q in value for q in ['"', "'", "`"])
    try:
        float(sv.rstrip(";,")); is_num = True
    except (ValueError, AttributeError):
        is_num = False
    if not has_quotes and not is_num:
        return None
    return s


class CodeBERT:
    def __init__(self, batch_size=32):
        import torch
        from transformers import AutoTokenizer, AutoModel
        self.torch = torch
        self.dev = "cuda" if torch.cuda.is_available() else ("mps" if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available() else "cpu")
        self.tok = AutoTokenizer.from_pretrained(CODEBERT_MODEL)
        self.model = AutoModel.from_pretrained(CODEBERT_MODEL).to(self.dev).eval()
        self.bs = batch_size
        log(f"[codebert] model loaded on {self.dev}")

    def embed(self, texts):
        """Masked mean pooling over last_hidden_state (identical to per-line mean(dim=1) with no padding)."""
        torch = self.torch
        out = []
        with torch.no_grad():
            for i in range(0, len(texts), self.bs):
                batch = texts[i:i + self.bs]
                enc = self.tok(batch, return_tensors="pt", padding=True, truncation=True, max_length=512).to(self.dev)
                h = self.model(**enc).last_hidden_state
                m = enc["attention_mask"].unsqueeze(-1).float()
                emb = (h * m).sum(1) / m.sum(1).clamp(min=1)
                out.append(torch.nn.functional.normalize(emb, dim=-1).cpu())
        return torch.cat(out) if out else torch.empty(0, 768)


def run_codebert(repo_dir: Path, out_file: Path, cb: "CodeBERT", kw_emb, kw_names, ignored_ext):
    if out_file.exists():
        return
    torch = cb.torch
    records = []
    texts, meta = [], []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in [".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build"]]
        for fn in files:
            if any(fn.endswith(e) for e in ignored_ext):
                continue
            fpath = Path(root) / fn
            rel = str(fpath.relative_to(repo_dir)).replace("\\", "/")
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue
            for ln, line in enumerate(lines, 1):
                s = candidate_line(line)
                if s is None:
                    continue
                texts.append(s); meta.append((rel, ln, s[:100]))
    if texts:
        for i in range(0, len(texts), 512):
            emb = cb.embed(texts[i:i + 512])            # (n, 768) normalized
            sims = emb @ kw_emb.T                        # cosine similarity to every keyword
            best, idx = sims.max(dim=1)
            for j in range(emb.shape[0]):
                b = float(best[j])
                if b >= SIM_FLOOR:
                    rel, ln, snip = meta[i + j]
                    records.append({"file": rel, "line": ln, "max_sim": round(b, 4),
                                    "keyword": kw_names[int(idx[j])], "snippet": snip})
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({"repo": repo_dir.name, "lines_analyzed": len(texts)}) + "\n")
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def stage_scan(a):
    data_dir, out = Path(a.data_dir), Path(a.out)
    split = load_split(out)
    repos = split["validation"] + split["test"]
    if a.max_repos:
        repos = repos[:a.max_repos]
    cb_dir = out / "codebert"
    cb_dir.mkdir(parents=True, exist_ok=True)

    if not a.skip_detect_secrets:
        variants = [("stock", None)] + ([("patched", patched_env())] if patched_available() else [])
        for name, env in variants:
            ds_dir = out / DS_VARIANTS[name]
            ds_dir.mkdir(parents=True, exist_ok=True)
            log(f"[scan] detect-secrets ({name}) over {len(repos)} repos")
            for i, r in enumerate(repos, 1):
                t0 = time.time()
                run_detect_secrets(data_dir / r, ds_dir / f"{r}.json", env)
                log(f"  [{i}/{len(repos)}] {r} ({time.time()-t0:.1f}s)")
        (out / "environment.json").write_text(json.dumps({
            "detect_secrets_variants": [v[0] for v in variants],
            "python": sys.version, "cwd": str(Path.cwd())}, indent=1))

    if not a.skip_codebert:
        kws = load_denylist_keywords()
        ignored = load_ignored_extensions()
        log(f"[scan] CodeBERT: {len(kws)} keyword patterns, {len(ignored)} ignored extensions")
        cb = CodeBERT(batch_size=a.batch_size)
        kw_emb = cb.embed(kws)
        (out / "codebert_keywords.json").write_text(json.dumps(kws, indent=1, ensure_ascii=False))
        for i, r in enumerate(repos, 1):
            t0 = time.time()
            run_codebert(data_dir / r, cb_dir / f"{r}.jsonl", cb, kw_emb, kws, ignored)
            log(f"  [{i}/{len(repos)}] {r} ({time.time()-t0:.1f}s)")
    log("[scan] done")


# --------------------------------------------------------------------------- #
# Loading scan results
# --------------------------------------------------------------------------- #
def load_scans(out: Path, repos, variant="stock"):
    """returns ds[repo] = {(file,line): type}, cb[repo] = {(file,line): (max_sim, keyword, snippet)}"""
    ds, cb = {}, {}
    for r in repos:
        p = out / DS_VARIANTS[variant] / f"{r}.json"
        ds[r] = {}
        if p.exists():
            for f in json.loads(p.read_text())["findings"]:
                ds[r][(f["file"], f["line"])] = f["type"]
        p = out / "codebert" / f"{r}.jsonl"
        cb[r] = {}
        if p.exists():
            with open(p, encoding="utf-8") as fh:
                next(fh, None)
                for line in fh:
                    d = json.loads(line)
                    cb[r][(d["file"], d["line"])] = (d["max_sim"], d["keyword"], d.get("snippet", ""))
    return ds, cb


def scanned_repos(out: Path, repos, variant="stock"):
    return [r for r in repos if (out / DS_VARIANTS[variant] / f"{r}.json").exists() and (out / "codebert" / f"{r}.jsonl").exists()]


def primary_variant(out: Path, repos):
    """patched if every repo has a patched scan, else stock"""
    return "patched" if repos and len(scanned_repos(out, repos, "patched")) == len(scanned_repos(out, repos, "stock")) > 0 else "stock"


def merged_candidates(ds_r, cb_r, thr):
    """union of detect-secrets findings and CodeBERT findings >= thr -> {(file,line): tools}"""
    m = {}
    for k in ds_r:
        m[k] = {"detect-secrets"}
    for k, (sim, _, _) in cb_r.items():
        if sim >= thr:
            m.setdefault(k, set()).add("codebert")
    return m


# --------------------------------------------------------------------------- #
# Stage: llm
# --------------------------------------------------------------------------- #
def llm_key(repo, file, line):
    return f"{repo}/{file}:{line}"


BAD_REASONS = {"LLM error", "Could not parse"}


def load_llm_cache(path: Path, drop_bad=False):
    """Later lines override earlier ones (re-queried records). drop_bad: ignore failed records so they get re-queried."""
    cache, bad = {}, 0
    if path.exists():
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                if drop_bad and d.get("reason") in BAD_REASONS:
                    bad += 1
                    continue
                cache[d["key"]] = d
    if drop_bad and bad:
        log(f"[llm] {bad} failed records in cache will be re-queried")
    return cache


def read_line(path: Path, ln: int):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        return lines[ln - 1].rstrip()
    except Exception as e:
        return f"Error reading file: {e}"


def load_openai_key():
    import configparser
    cfg = configparser.ConfigParser()
    cfg.read("config.ini")
    key = cfg.get("API_KEYS", "openai_api_key", fallback="") if cfg.has_section("API_KEYS") else ""
    return key or os.environ.get("OPENAI_API_KEY", "")


def parse_llm_json(text):
    """Robust parse of the model's JSON reply (the 'reason' field may itself contain braces/quotes)."""
    if not text:
        return None
    # 1) whole reply / fenced block / outermost braces
    for cand in (text, re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M),
                 text[text.find("{"): text.rfind("}") + 1] if "{" in text and "}" in text else ""):
        try:
            d = json.loads(cand)
            if isinstance(d, dict) and "is_false_positive" in d:
                return d
        except Exception:
            pass
    # 2) field-level fallback
    m_fp = re.search(r'"is_false_positive"\s*:\s*(true|false)', text, re.I)
    if not m_fp:
        return None
    m_conf = re.search(r'"confidence"\s*:\s*"(high|medium|low)"', text, re.I)
    m_reason = re.search(r'"reason"\s*:\s*"(.*)', text, re.S)
    return {"is_false_positive": m_fp.group(1).lower() == "true",
            "confidence": (m_conf.group(1).lower() if m_conf else "low"),
            "reason": (m_reason.group(1).strip().rstrip('"}\n ') if m_reason else ""), "_fallback_parse": True}


def query_openai(client, model, context):
    prompt = PROMPT_TEMPLATE.format(context=context)
    for attempt in range(8):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": "You are a security expert analyzing code for secrets."},
                          {"role": "user", "content": prompt}],
                temperature=LLM_TEMPERATURE)
            text = resp.choices[0].message.content
            usage = getattr(resp, "usage", None)
            parsed = parse_llm_json(text)
            if parsed is None:      # genuinely unparseable -> same default as the original tool (not a FP)
                parsed = {"is_false_positive": False, "confidence": "low", "reason": "Could not parse", "_unparsed": text[:300]}
            return parsed, text, (usage.prompt_tokens if usage else 0), (usage.completion_tokens if usage else 0)
        except Exception as e:
            name = e.__class__.__name__
            wait = min(60, (2 ** attempt) * (3 if "RateLimit" in name else 1)) + random.random()
            log(f"    llm error ({name}): {str(e)[:100]} — retry in {wait:.0f}s")
            time.sleep(wait)
    return {"is_false_positive": False, "confidence": "low", "reason": "LLM error"}, "", 0, 0


def select_llm_repos(split, n, seed):
    rng = random.Random(seed)
    test = list(split["test"])
    rng.shuffle(test)
    return sorted(test[:n]) if n else sorted(split["test"])


def stage_llm(a):
    data_dir, out = Path(a.data_dir), Path(a.out)
    split = load_split(out)
    repos = select_llm_repos(split, a.llm_repos, a.seed)
    repos = scanned_repos(out, repos)
    variant = a.variant or primary_variant(out, repos)
    (out / "llm_repos.json").write_text(json.dumps({"repos": repos, "n": a.llm_repos, "seed": a.seed, "threshold": a.threshold, "variant": variant}, indent=1))
    ds, cb = load_scans(out, repos, variant)
    log(f"[llm] rule-based variant: {variant}")

    gt = load_ground_truth(Path(a.meta_dir), repos)
    work, skipped_unlabeled = [], 0
    for r in repos:
        labeled = {(f, ln) for f, lines in gt.get(r, {}).items() for ln in lines}
        for (f, ln), tools in merged_candidates(ds[r], cb[r], a.threshold).items():
            if a.labeled_only and (f, ln) not in labeled:
                skipped_unlabeled += 1        # not part of the metrics (CredData convention) -> no need to pay for them
                continue
            work.append((r, f, ln, sorted(tools)))
    if a.labeled_only:
        log(f"[llm] skipping {skipped_unlabeled} candidates on unlabeled lines (not counted in metrics)")
    cache_path = out / f"llm_{a.model}.jsonl"
    cache = load_llm_cache(cache_path, drop_bad=True)
    todo = [w for w in work if llm_key(w[0], w[1], w[2]) not in cache]
    log(f"[llm] repos={len(repos)} candidates@{a.threshold}={len(work)} cached={len(work)-len(todo)} todo={len(todo)}")
    est_tokens = len(todo) * 330
    log(f"[llm] rough cost estimate for todo: ~{est_tokens/1e6:.2f}M tokens (~${est_tokens/1e6*0.6:.2f} at gpt-4.1-mini input pricing)")
    if a.dry_run or not todo:
        return
    if a.limit:
        todo = todo[:a.limit]

    from openai import OpenAI
    key = load_openai_key()
    if not key:
        sys.exit("OpenAI API key not found (config.ini [API_KEYS] openai_api_key or OPENAI_API_KEY env)")
    client = OpenAI(api_key=key)

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def work_item(item):
        r, f, ln, tools = item
        context = read_line(data_dir / r / f, ln)
        parsed, raw, pt, ct = query_openai(client, a.model, context)
        return {"key": llm_key(r, f, ln), "repo": r, "file": f, "line": ln, "tools": tools,
                "context": context[:300],
                "is_false_positive": bool(parsed.get("is_false_positive", False)),
                "confidence": str(parsed.get("confidence", "low")).lower(),
                "reason": parsed.get("reason", ""), "prompt_tokens": pt, "completion_tokens": ct,
                "model": a.model}

    done = 0
    with open(cache_path, "a", encoding="utf-8") as fh, ThreadPoolExecutor(max_workers=a.workers) as ex:
        futures = [ex.submit(work_item, it) for it in todo]
        for fut in as_completed(futures):
            rec = fut.result()
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n"); fh.flush()
            done += 1
            if done % 100 == 0 or done == len(todo):
                log(f"  [{done}/{len(todo)}] last: fp={rec['is_false_positive']} conf={rec['confidence']}")
    log("[llm] done")


# --------------------------------------------------------------------------- #
# Stage: eval
# --------------------------------------------------------------------------- #
def metrics(tp, fp, tn, fn):
    def div(x, y): return x / y if y else 0.0
    p, r = div(tp, tp + fp), div(tp, tp + fn)
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "precision": p, "recall": r, "f1": div(2 * p * r, p + r),
            "FPR": div(fp, fp + tn), "FNR": div(fn, fn + tp),
            "accuracy": div(tp + tn, tp + fp + tn + fn)}


def evaluate(gt, repos, predicted):
    """
    predicted: {repo: set((file,line))} lines reported as secrets.
    CredData convention: only marked-up lines count. T = positive; F and X = negative.
    Reported lines without markup are counted separately as 'unlabeled' (not in P/R).
    A multi-line markup is matched if any of its lines is reported.
    """
    tp = fp = tn = fn = 0
    unlabeled = 0
    per_cat = defaultdict(lambda: [0, 0])          # category -> [tp, total_T]
    for r in repos:
        g = gt.get(r, {})
        pred = predicted.get(r, set())
        # group markup by (file, line_start)
        markups = {}
        for f, lines in g.items():
            for ln, d in lines.items():
                markups.setdefault((f, d["line_start"]), {"label": d["label"], "cat": d["category"], "lines": set()})["lines"].add(ln)
        labeled_lines = {(f, ln) for f, lines in g.items() for ln in lines}
        for (f, ls), m in markups.items():
            hit = any((f, ln) in pred for ln in m["lines"])
            if m["label"] == "T":
                per_cat[m["cat"].split(":")[0]][1] += 1
                if hit:
                    tp += 1; per_cat[m["cat"].split(":")[0]][0] += 1
                else:
                    fn += 1
            else:
                if hit: fp += 1
                else: tn += 1
        unlabeled += sum(1 for k in pred if k not in labeled_lines)
    res = metrics(tp, fp, tn, fn)
    res["unlabeled_reported"] = unlabeled
    res["per_category_recall"] = {c: {"tp": v[0], "total": v[1], "recall": (v[0] / v[1] if v[1] else 0)} for c, v in sorted(per_cat.items())}
    return res


def predictions(ds, cb, repos, config, thr, llm=None):
    """config in {'regex','codebert','union'}; llm cache dict -> filter out is_false_positive."""
    out = {}
    for r in repos:
        s = set()
        if config in ("regex", "union"):
            s |= set(ds[r].keys())
        if config in ("codebert", "union"):
            s |= {k for k, (sim, _, _) in cb[r].items() if sim >= thr}
        if llm is not None:
            s = {k for k in s if not llm.get(llm_key(r, k[0], k[1]), {}).get("is_false_positive", False)}
        out[r] = s
    return out


def fmt_row(name, m):
    return f"| {name} | {m['TP']} | {m['FP']} | {m['FN']} | {m['TN']} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['FPR']:.3f} | {m['FNR']:.3f} |"


TABLE_HDR = "| Configuration | TP | FP | FN | TN | Precision | Recall | F1 | FPR | FNR |\n|---|---|---|---|---|---|---|---|---|---|"


def stage_eval(a):
    out = Path(a.out)
    split = load_split(out)
    meta_dir = Path(a.meta_dir)
    val = scanned_repos(out, split["validation"])
    test = scanned_repos(out, split["test"])
    log(f"[eval] scanned repos: validation={len(val)}/{len(split['validation'])} test={len(test)}/{len(split['test'])}")
    excl = tuple(c.strip() for c in (a.exclude_categories or "").split(",") if c.strip())
    gt = load_ground_truth(meta_dir, val + test, exclude_x=a.exclude_x, exclude_categories=excl)
    suffix = ("_noX" if a.exclude_x else "") + ("".join(f"_no{c.replace(' ', '')}" for c in excl))
    variant = a.variant or primary_variant(out, val + test)
    other = "stock" if variant == "patched" else "patched"
    ds, cb = load_scans(out, val + test, variant)
    ds_other = load_scans(out, val + test, other)[0] if len(scanned_repos(out, test, other)) == len(test) else None
    log(f"[eval] rule-based variant: {variant}" + (f" (+ {other} for comparison)" if ds_other else ""))
    report = {"split": {"validation": len(val), "test": len(test)}, "detect_secrets_variant": variant,
              "gt_counts": {"validation": dict(zip("TFX", gt_counts(gt, val))), "test": dict(zip("TFX", gt_counts(gt, test)))}}
    md = ["# Benchmark results (CredData)\n",
          f"Validation: {len(val)} repos (T={report['gt_counts']['validation']['T']}, F={report['gt_counts']['validation']['F']}, X={report['gt_counts']['validation']['X']}); "
          f"Test: {len(test)} repos (T={report['gt_counts']['test']['T']}, F={report['gt_counts']['test']['F']}, X={report['gt_counts']['test']['X']}). "
          f"Negatives = F{'' if a.exclude_x else ' + X'} (CredData convention). Reported lines without markup are not counted. "
          f"Rule-based = detect-secrets 1.5.0 **{variant}**."
          + (f" **Excluded CredData categories: {', '.join(excl)}** (both T and F rows of these categories are removed from the evaluation universe)." if excl else "") + "\n"]

    # ---- 0. distribution of CodeBERT max-similarity (explains the flat sweep / anisotropy) ----
    sims = sorted(v[0] for r in val for v in cb[r].values())
    if sims:
        q = lambda p: sims[min(len(sims) - 1, int(p * len(sims)))]
        dist = {"n_lines_stored(>=0.60)": len(sims), "min": sims[0], "p5": q(.05), "p25": q(.25), "median": q(.5), "p75": q(.75), "p95": q(.95), "max": sims[-1],
                "share_>=0.85": sum(x >= 0.85 for x in sims) / len(sims), "share_>=0.90": sum(x >= 0.90 for x in sims) / len(sims)}
        report["codebert_similarity_distribution_validation"] = dist
        md.append("## CodeBERT max-cosine-similarity distribution (validation, all pre-filtered assignment lines)\n")
        md.append("| n | min | p5 | p25 | median | p75 | p95 | max | share ≥0.85 | share ≥0.90 |\n|---|---|---|---|---|---|---|---|---|---|")
        md.append(f"| {dist['n_lines_stored(>=0.60)']} | {dist['min']:.3f} | {dist['p5']:.3f} | {dist['p25']:.3f} | {dist['median']:.3f} | {dist['p75']:.3f} | {dist['p95']:.3f} | {dist['max']:.3f} | {dist['share_>=0.85']:.1%} | {dist['share_>=0.90']:.1%} |\n")

    # ---- 1. threshold sweep on validation ----
    sweep_rows = []
    for thr in SWEEP:
        m_cb = evaluate(gt, val, predictions(ds, cb, val, "codebert", thr))
        m_un = evaluate(gt, val, predictions(ds, cb, val, "union", thr))
        flagged = sum(1 for r in val for v in cb[r].values() if v[0] >= thr)
        sweep_rows.append({"threshold": thr, "codebert_flagged_lines": flagged,
                           **{f"codebert_{k}": m_cb[k] for k in ("precision", "recall", "f1", "FPR", "FNR", "TP", "FP")},
                           **{f"union_{k}": m_un[k] for k in ("precision", "recall", "f1", "FPR", "FNR", "TP", "FP")}})
    with open(out / f"threshold_sweep_validation{suffix}.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(sweep_rows[0].keys())); w.writeheader(); w.writerows(sweep_rows)
    # tie-break: higher F1, then higher precision, then higher threshold (fewer LLM calls)
    best_cb = max(sweep_rows, key=lambda r: (round(r["codebert_f1"], 6), round(r["codebert_precision"], 6), r["threshold"]))
    best_un = max(sweep_rows, key=lambda r: (round(r["union_f1"], 6), round(r["union_precision"], 6), r["threshold"]))
    report["threshold_sweep"] = {"best_codebert_only": best_cb, "best_union": best_un}
    md.append("## Threshold sweep (validation split)\n")
    md.append("| thr | flagged lines | CodeBERT P | R | F1 | FPR | Union P | R | F1 | FPR |\n|---|---|---|---|---|---|---|---|---|---|")
    for r in sweep_rows:
        if abs(r["threshold"] * 100 % 5) < 1e-6 or r["threshold"] in (best_cb["threshold"], best_un["threshold"], DEFAULT_THRESHOLD):
            md.append(f"| {r['threshold']:.2f} | {r['codebert_flagged_lines']} | {r['codebert_precision']:.3f} | {r['codebert_recall']:.3f} | {r['codebert_f1']:.3f} | {r['codebert_FPR']:.3f} "
                      f"| {r['union_precision']:.3f} | {r['union_recall']:.3f} | {r['union_f1']:.3f} | {r['union_FPR']:.3f} |")
    md.append(f"\nBest F1 on validation: CodeBERT-only at **{best_cb['threshold']:.2f}** (F1={best_cb['codebert_f1']:.3f}); "
              f"union at **{best_un['threshold']:.2f}** (F1={best_un['union_f1']:.3f}). Paper default: {DEFAULT_THRESHOLD}.\n")
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        xs = [r["threshold"] for r in sweep_rows]
        fig, ax = plt.subplots(figsize=(6, 3.5))
        for k, lab in (("codebert_precision", "Precision"), ("codebert_recall", "Recall"), ("codebert_f1", "F1")):
            ax.plot(xs, [r[k] for r in sweep_rows], label=lab)
        ax.axvline(DEFAULT_THRESHOLD, ls="--", c="gray", lw=0.8); ax.axvline(best_cb["threshold"], ls=":", c="black", lw=0.8)
        ax.set_xlabel("cosine similarity threshold"); ax.set_ylabel("score"); ax.set_title("CodeBERT-only, validation split")
        ax.legend(); fig.tight_layout(); fig.savefig(out / f"threshold_sweep_validation{suffix}.png", dpi=200)
    except Exception as e:
        log(f"[eval] plot skipped: {e}")

    # ---- 2. ablation on test (no LLM) ----
    # operational threshold = the one that maximises F1 of the deployed configuration (union) on validation
    thr_sel = best_un["threshold"]
    md.append(f"## Ablation without LLM (test split, {len(test)} repos)\n")
    md.append(TABLE_HDR)
    abl = {}
    if ds_other:
        m = evaluate(gt, test, {r: set(ds_other[r].keys()) for r in test})
        abl[f"Rule-based ({other} detect-secrets)"] = m; md.append(fmt_row(f"Rule-based ({other} detect-secrets)", m))
    for name, cfg, thr in ((f"Rule-based ({variant} detect-secrets)", "regex", None),
                           (f"CodeBERT only @{DEFAULT_THRESHOLD}", "codebert", DEFAULT_THRESHOLD),
                           (f"CodeBERT only @{thr_sel} (val-selected)", "codebert", thr_sel),
                           (f"Union @{DEFAULT_THRESHOLD}", "union", DEFAULT_THRESHOLD),
                           (f"Union @{thr_sel} (val-selected)", "union", thr_sel)):
        m = evaluate(gt, test, predictions(ds, cb, test, cfg, thr or 0))
        abl[name] = m; md.append(fmt_row(name, m))
    report["ablation_test_no_llm"] = abl

    # ---- 3. ablation with LLM (on the LLM repo subset of test) ----
    llm_path = out / f"llm_{a.model}.jsonl"
    llm_info = out / "llm_repos.json"
    if llm_path.exists() and llm_info.exists():
        llm = load_llm_cache(llm_path)
        info = json.loads(llm_info.read_text())
        lrepos = [r for r in info["repos"] if r in test]
        thr_llm = info.get("threshold", DEFAULT_THRESHOLD)
        if info.get("variant", "stock") != variant:
            ds, _ = load_scans(out, lrepos, info.get("variant", "stock"))
            md.append(f"\n_(LLM candidates were generated with the **{info.get('variant')}** rule-based variant.)_")
        # only lines that actually have an LLM decision are meaningful; warn about coverage
        cand = merged_total = 0
        for r in lrepos:
            for k in merged_candidates(ds[r], cb[r], thr_llm):
                merged_total += 1
                cand += llm_key(r, k[0], k[1]) in llm
        md.append(f"\n## Ablation with LLM verification (test subset: {len(lrepos)} repos, {a.model}, candidates @{thr_llm}; LLM coverage {cand}/{merged_total})\n")
        md.append(TABLE_HDR)
        abl2 = {}
        for name, cfg, use_llm in (("Rule-based", "regex", False), ("Rule-based + LLM", "regex", True),
                                   ("CodeBERT", "codebert", False), ("CodeBERT + LLM", "codebert", True),
                                   ("Union (hybrid, no LLM)", "union", False), ("Union + LLM (full pipeline)", "union", True)):
            m = evaluate(gt, lrepos, predictions(ds, cb, lrepos, cfg, thr_llm, llm if use_llm else None))
            abl2[name] = m; md.append(fmt_row(name, m))
        report["ablation_test_with_llm"] = abl2
        # confidence breakdown of LLM decisions vs ground truth
        conf = Counter()
        for r in lrepos:
            g = gt.get(r, {})
            for k, v in llm.items():
                if v["repo"] != r: continue
                lab = g.get(v["file"], {}).get(v["line"], {}).get("label", "unlabeled")
                conf[(v["confidence"], "FP" if v["is_false_positive"] else "TP", lab)] += 1
        md.append("\n### LLM decision × confidence × ground truth (test subset)\n")
        md.append("| LLM says | confidence | GT=T | GT=F | GT=X | unlabeled |\n|---|---|---|---|---|---|")
        for says in ("TP", "FP"):
            for c in ("high", "medium", "low"):
                md.append(f"| {'secret' if says=='TP' else 'false positive'} | {c} | " + " | ".join(str(conf[(c, says, l)]) for l in ("T", "F", "X", "unlabeled")) + " |")
        report["llm_confidence_breakdown"] = {f"{k[0]}|{k[1]}|{k[2]}": v for k, v in conf.items()}
        tok = sum(v.get("prompt_tokens", 0) + v.get("completion_tokens", 0) for v in llm.values())
        md.append(f"\nLLM calls: {len(llm)}, tokens: {tok:,}\n")
    else:
        md.append("\n_LLM stage not run yet — `python run_benchmark.py llm` to add the +LLM rows._\n")

    # ---- 4. per-category recall for full pipeline w/o LLM ----
    m = abl[f"Union @{DEFAULT_THRESHOLD}"]
    md.append(f"\n## Per-category recall, Union @{DEFAULT_THRESHOLD} (test split)\n\n| Category | T total | detected | recall |\n|---|---|---|---|")
    for c, v in m["per_category_recall"].items():
        if v["total"] >= 20:
            md.append(f"| {c} | {v['total']} | {v['tp']} | {v['recall']:.3f} |")

    (out / f"results{suffix}.md").write_text("\n".join(md), encoding="utf-8")
    (out / f"metrics{suffix}.json").write_text(json.dumps(report, indent=1, default=float), encoding="utf-8")
    log("\n".join(md))
    log(f"\n[eval] written {out/f'results{suffix}.md'}, {out/f'metrics{suffix}.json'}, {out/f'threshold_sweep_validation{suffix}.csv'}")


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    ap.add_argument("--meta-dir", default=DEFAULT_META_DIR)
    ap.add_argument("--out", default=DEFAULT_OUT_DIR)
    ap.add_argument("--seed", type=int, default=42)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("check")
    s = sub.add_parser("split"); s.add_argument("--val-frac", type=float, default=0.2)
    s = sub.add_parser("scan")
    s.add_argument("--max-repos", type=int, default=0, help="limit for a quick trial run")
    s.add_argument("--batch-size", type=int, default=32)
    s.add_argument("--skip-detect-secrets", action="store_true")
    s.add_argument("--skip-codebert", action="store_true")
    s = sub.add_parser("llm")
    s.add_argument("--llm-repos", type=int, default=0, help="number of TEST repos to verify with the LLM (0 = all test repos)")
    s.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    s.add_argument("--model", default=LLM_MODEL)
    s.add_argument("--limit", type=int, default=0, help="max API calls this run (resumable)")
    s.add_argument("--dry-run", action="store_true", help="only count candidates and estimate cost")
    s.add_argument("--workers", type=int, default=4, help="parallel API requests (lower if you hit 429s)")
    s.add_argument("--all-lines", dest="labeled_only", action="store_false", default=True,
                   help="also send candidates on unlabeled lines (default: only CredData-labeled lines)")
    s.add_argument("--variant", choices=list(DS_VARIANTS), default=None, help="rule-based variant for candidates (default: patched if available)")
    s = sub.add_parser("eval")
    s.add_argument("--model", default=LLM_MODEL)
    s.add_argument("--variant", choices=list(DS_VARIANTS), default=None, help="rule-based variant (default: patched if available)")
    s.add_argument("--exclude-x", action="store_true", help="drop X-labelled rows instead of counting them as negatives")
    s.add_argument("--exclude-categories", default="", help='comma-separated CredData categories to drop from the evaluation, e.g. "UUID"')

    a = ap.parse_args()
    {"check": stage_check, "split": stage_split, "scan": stage_scan, "llm": stage_llm, "eval": stage_eval}[a.cmd](a)


if __name__ == "__main__":
    main()
