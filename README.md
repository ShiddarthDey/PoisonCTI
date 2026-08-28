# PoisonCTI

**Single-source RAG poisoning of LLM-based CVE severity assessment, and a consistency-based defense.**

PoisonCTI studies whether a *single* poisoned document inside a retrieval-augmented generation (RAG) corpus can steer an LLM's CVSS-style severity verdict for a target CVE — and whether a leave-one-out consistency check can detect and recover from such manipulation without any trusted data.

## Key findings

Three open-weight models, 8 attack scenarios each (4 deflate, 4 inflate), temperature 0:

| Model | Attack success | Defense detection | Severity recovery | False positives |
|---|---|---|---|---|
| Llama 3 8B | 8/8 | 8/8 | 8/8 (1.00) | 0/8 |
| Qwen 2.5 7B | 7/8 | 7/8 | 7/8 (0.88) | 0/8 |
| Mistral 7B | 4/8 | 7/8 | 8/8 (1.00) | 0/8 |

- Attack susceptibility is **model-dependent** (8/8 vs 4/8 across models on identical inputs).
- The leave-one-out defense **generalizes across models**: ≥7/8 detection and **zero false positives** on clean runs everywhere.
- The attack/defense asymmetry (inflation vs deflation shifts) is model-specific, not universal — see the paper, §V.

## Repository layout

```
config/
  models.lock.json      # Pinned model digests (reproducibility lock)
scripts/
  00_pin_models.py      # Record exact Ollama model digests before running
  01–03                 # Corpus & attack scenario construction
  04_*.py               # Attack runs (poisoned RAG severity assessment)
  05_run_defense.py     # Leave-one-out consistency defense evaluation
  06_evaluate.py        # Metrics, tables, and narrative generation (data-driven)
RESULTS.md              # Llama 3 8B results
RESULTS_qwen2.5-7b.md   # Qwen 2.5 7B results
RESULTS_mistral-7b.md   # Mistral 7B results
main.tex                # Paper source (IEEE format)
references.bib
```

## Reproducing

Requires [Ollama](https://ollama.com) and Python 3.10+.

1. Pull and pin the exact models used:
   ```bash
   ollama pull llama3:8b && ollama pull qwen2.5:7b && ollama pull mistral:7b
   python scripts/00_pin_models.py --add <model>
   ```
   `config/models.lock.json` records the digest of every model; runs verify against it so results cannot silently drift across model updates.
2. Run the pipeline stages in order (`04` attack → `05` defense → `06` evaluation). Stage 05 rebuilds its inputs from the attack run; stage 06 regenerates all tables and the results narrative from stored outputs.
3. Per-run artifacts (prompts, raw model outputs, verdicts) are stored under timestamped `run_*` directories and are the source of every number in the paper.

## Paper

`main.tex` compiles with pdfLaTeX (IEEEtran). All tables are generated from run artifacts; see `06_evaluate.py`.

## Citation

```bibtex
@misc{poisoncti2026,
  author = {Tusar, Shiddarth Dey},
  title  = {PoisonCTI: Single-Source RAG Poisoning of LLM-Based CVE Severity Assessment},
  year   = {2026},
  howpublished = {\url{https://github.com/ShiddarthDey/PoisonCTI}}
}
```

## Contact

Shiddarth Dey Tusar — Charles Sturt University, NSW, Australia — tusardey77@gmail.com
