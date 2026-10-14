# Hafiye

Hafiye finds secrets (passwords, API keys, tokens, private keys) in source code. It is the code of the paper *Hybrid Approach for Sensitive Information Detection in Source Code Using Rule-Based, Vector-Based, and LLM-Assisted Filtering* (M. C. Sözeri, Ç. N. Yuva, S. Sarp, Gebze Technical University).

The name comes from the Ottoman word *hafiye*, a person who finds hidden things.

Hafiye has three steps:

1. **Rule-based:** detect-secrets 1.5.0
2. **Vector-based:** heuristic pre-filters + CodeBERT similarity to secret keywords (threshold 0.85)
3. **LLM verification:** gpt-4.1-mini checks each candidate and marks it as secret or false positive

## Files

| File | Purpose |
|---|---|
| `secret_scanner_main.py` | The scanner (local folder or GitHub URL) |
| `benchmark.py` | Downloads the Samsung CredData data set |
| `run_benchmark.py` | Benchmark: split, scan, LLM step, metrics, threshold sweep |
| `paper_tables.py` | Builds all tables, Figure 3 and the other numbers of the paper |
| `analyze_llm_fn.py` | Analysis of true secrets rejected by the LLM |
| `setup_patched_tools.py` | Builds the customised detect-secrets variant |
| `upgrade/` | Changed files used by `benchmark.py` and `setup_patched_tools.py` |

## Setup

Python 3.11 was used.

```bash
git clone https://github.com/mcansozeri/hafiye.git
cd hafiye
pip install -r requirements.txt
python setup_patched_tools.py         # customised detect-secrets -> tools/detect-secrets-patched
cp config.ini.example config.ini      # add your OpenAI (or Gemini) API key
```

PyEnchant needs the enchant library (macOS: `brew install enchant`, Ubuntu: `apt install libenchant-2-2`).

## Scanning a project

```bash
python secret_scanner_main.py /path/to/project
python secret_scanner_main.py https://github.com/user/repo
python secret_scanner_main.py /path/to/project --no-llm
```

| Option | Default | |
|---|---|---|
| `--similarity-threshold` | 0.85 | CodeBERT threshold |
| `--detect-secrets {patched,stock}` | patched | customised or stock detect-secrets |
| `--llm-provider {openai,gemini}` | openai | LLM for the verification step |
| `--context-lines` | 0 | lines around the finding sent to the LLM |
| `--no-llm` | | skip the LLM step |

Results are written to `results/<scan-id>/`: `detect-secrets.json`, `codebert.json`, `merged.json`, `llm-analyzed-all.json`, `final-true-positives.json`, `statistics.json` and `scan_summary.txt`.

## Reproducing the paper results

```bash
python benchmark.py                 # download CredData into benchmark/CredData/data
python setup_patched_tools.py
python run_benchmark.py check
python run_benchmark.py split       # repository-level split, seed 42
python run_benchmark.py scan        # detect-secrets (stock and customised) + CodeBERT
python run_benchmark.py llm         # LLM verification on the test split (paid API calls)
python run_benchmark.py eval
python paper_tables.py              # -> benchmark_results/paper_tables.md
python analyze_llm_fn.py
```

- CredData is still being updated, so the scripts use fixed versions: the December 2025 snapshot for the data and the September 2026 labels for the evaluation. A new download gives the same 331 repositories and the same split. A few files differ from our download, so the counts can differ slightly (for example, stock detect-secrets on the test split: precision 0.723 and recall 0.145 instead of 0.722 and 0.144).
- `python run_benchmark.py llm --dry-run` shows the number of candidates and the expected cost before any API call. In our run the LLM step for the test split (12,100 candidates) cost about 3.5 USD.
- All steps can be resumed. The data set is not included in this repository; CredData is available at https://github.com/Samsung/CredData.
- The LLM answers are not fully deterministic (temperature 0.3), so a new LLM run can give slightly different numbers. With the same `benchmark_results/llm_gpt-4.1-mini.jsonl` file, `paper_tables.py` gives the same tables.

## License

CC BY-NC 4.0. See `LICENSE`.
