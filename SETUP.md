# SETUP — PoisonCTI

Everything runs **locally and for free**. No paid APIs, no cloud GPU. The only
moving server is [Ollama](https://ollama.com), which serves both the chat model
and the embedding model.

## 1. Prerequisites

- **Python 3.10–3.12** (3.11 recommended).
- **Ollama** installed and running locally. Verify with `ollama --version`.
- ~6 GB free disk (models + corpus + index).
- (Optional) an **NVD API key** — free, raises rate limits. Without it, NVD still
  works but throttles to a few requests/minute. Get one at
  https://nvd.nist.gov/developers/request-an-api-key

## 2. Pull the local models

```bash
ollama pull llama3        # or: mistral  — the agent's reasoning model
ollama pull bge-m3             # the embedding model for the RAG corpus (1024-dim)
```

Both are free and run on CPU. The model names are configurable in
`config/settings.yaml` (see step 4), so swapping `llama3` ↔ `mistral` is a one-line
change — useful for showing your results are not model-specific.

## 3. Create the environment

```bash
python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
pip install -e .          # makes `import poisoncti` work (uses pyproject.toml)
```

After a successful install, freeze the exact transitive graph for reproducibility:

```bash
pip freeze > requirements.lock
```

Commit `requirements.lock` so a reviewer can reproduce your exact environment.

## 4. Configure

```bash
cp config/settings.example.yaml config/settings.yaml   # PowerShell: copy ...
# (optional) put your NVD key in a .env file:
echo "NVD_API_KEY=your-key-here" > .env
```

`config/settings.yaml` is gitignored-by-convention for local overrides; the
committed `settings.example.yaml` documents every option (model names, paths,
retrieval `k`, defense thresholds).

## 5. Pin the models by digest (once per machine)

After pulling the models, capture their exact digests and commit the lock:

```bash
python scripts/00_pin_models.py     # writes config/models.lock.json
```

Paste the printed table into the README. Every run from here on verifies the live
models against this lock and aborts if a digest drifted (i.e. a model was re-pulled).

## 6. Reproduce — one command

```bash
python run_all.py        # == make reproduce
```

This sets the global seed, verifies model pins, builds the provenance stamp, and
runs steps 01–06 in order, stopping at the first failure. Each results file is
written with a `_provenance` block (model digests, seed, timestamp).

Run the steps individually if you prefer:

```bash
python scripts/01_download_data.py    # fetch ATT&CK STIX, NVD CVEs, CTI text
python scripts/02_build_corpus.py     # chunk + embed + index the CTI corpus
python scripts/03_run_baseline.py     # agent on the CLEAN corpus  -> baseline outputs
python scripts/04_run_poison.py       # inject ONE poisoned source -> poisoned outputs
python scripts/05_run_defense.py      # re-run with the consistency check enabled
python scripts/06_evaluate.py         # compute metrics + figures into results/
```

> The pipeline steps are scaffold stubs this session; the reproducibility harness
> (seed, digest pinning, provenance, run_all.py) is real and tested.

## 7. Verify the install (smoke test)

```bash
python -c "import poisoncti, numpy, ollama; print('env OK')"
ollama list    # should show llama3 (or mistral) and bge-m3
pytest -q      # scaffold tests should collect (and skip) cleanly
```

---

## Threat model (one paragraph)

We study an LLM-based threat-intelligence agent that ingests open-source CTI
(CISA advisories, vendor blogs, OTX-style pulses) into a retrieval corpus and,
when asked about a threat or a CVE, retrieves the most relevant CTI text and uses
a local LLM to (a) map the activity to MITRE ATT&CK techniques and (b) score the
CVE's severity. The attacker is an ordinary open-source contributor: they cannot
retrain the model, change the prompts, or touch the agent's code — they can only
get a single poisoned document accepted into the public CTI corpus, exactly as
anyone can publish a blog post or submit a pulse. Their goal is to steer the
agent's output: make it attribute the wrong ATT&CK technique, or inflate/deflate
a CVE's severity, for chosen items — while the poisoned source looks plausible and
the honest sources remain unchanged. The defender controls only the agent side and
wants a lightweight, no-retraining fix: a cross-source consistency check that flags
when one source disagrees with the broader retrieved evidence, restoring reliable
output without rebuilding the model. (Full version, including in/out of scope, in
[THREAT_MODEL.md](THREAT_MODEL.md).)
