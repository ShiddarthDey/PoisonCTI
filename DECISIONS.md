# DECISIONS.md

Running log of non-trivial choices and the one-line WHY behind each, so the
project stays explainable. Newest milestone at the bottom.

## Session 1 — scaffold & architecture

- **Thin hand-rolled agent (no LangChain).** WHY: a PhD project must be readable
  end-to-end; frameworks hide control flow and bloat the dependency surface.
- **RAG over a CTI corpus (not single-doc analysis).** WHY: makes "inject ONE
  poisoned source among many" a realistic, clean threat model.
- **`poison/` and `defense/` are siblings of `agent/`; agent never imports them.**
  WHY: enforces the scientific control — any steering must come from data alone.
- **Evaluation split into gold / metrics / experiment.** WHY: mirrors the two
  reported measures (gold-drift + ASR) and isolates the ambiguity-exclusion policy.
- **src-layout + minimal pyproject; deps only in requirements.txt.** WHY: standard
  for clean/citable repos; honors the "pinned requirements.txt" choice.
- **Embeddings via Ollama (`nomic-embed-text`), not sentence-transformers.** WHY:
  one local server for chat + embeddings; avoids a ~2GB PyTorch dependency.

## Session 2 — reproducibility harness

- **Model pinned by digest, verified at runtime.** `settings.yaml` holds the tag,
  `models.lock.json` holds the machine-resolved digest; runs abort on drift. WHY:
  a silently re-pulled model must never quietly change results.
- **Single global `seed` feeds RNG + Ollama decode `seed`; temperature=0.** WHY:
  deterministic agent judgements on a given machine.
- **Provenance block stamped into every results file.** WHY: each output is
  self-describing (model digest, seed, timestamp) and reproducible.
- **`run_all.py` is the single reproduce command (Makefile dropped).** WHY:
  Windows-first; one cross-platform entry point with `--clean` and `--no-verify`.
- **`io.py`/`reproducibility.py` implemented for real and unit-tested.** WHY:
  model-independent infrastructure belongs under test now (caught a default-arg
  binding bug in `build_provenance`).

## Session 3 — M1: Ingestion

- **Parse the ATT&CK STIX bundle with stdlib `json`; dropped `stix2` dep.** WHY:
  the bundle is plain JSON; removes a heavy install for no benefit.
- **Explicit, committed study set of CVE IDs (`data/study_set/cve_ids.json`),
  fetched by exact ID — not "latest N".** WHY: makes the whole study deterministic
  and lets gold/CTI/poison align to known, well-documented CVEs.
- **Study set seeded with well-known CVEs (Log4Shell, EternalBlue, Heartbleed,
  Zerologon, ProxyLogon, BlueKeep, …).** WHY: rich public CTI + clear ATT&CK
  mappings make the M6 gold curation tractable and defensible.
- **`config/settings.test.yaml` = first 2 CVEs, tiny corpus.** WHY: full
  clean→poison→defense→evaluate loop runs in seconds for CI-style checks.
- **Seed CTI is authored fixtures from public facts (committed JSON), not scraped.**
  WHY: reproducible and stable (no HTML-scraping fragility); first 3 CVEs get TWO
  sources each so the M5 cross-source check has material. NOTE: can be supplemented
  with real scraped advisories later if desired.
- **Honest seed CTI severities aligned to NVD gold (fixed EternalBlue 8.1→8.8).**
  WHY: honest sources must not misstate severity, or the baseline itself "steers."
- **Gold severity prefers CVSS v3.1 → v3.0 → v2 and records which was used.** WHY:
  honest provenance; not all CVEs carry every CVSS version.
- **Drop the `_provenance` stamp from ingestion outputs.** WHY: ingestion is
  model-independent (no LLM/seed effect); provenance starts at agent runs (M3+).
- **Deferred (needs your input at M6):** ATT&CK CVE→technique gold curation —
  will propose a draft with ambiguity flags + a Cohen's κ inter-annotator step.

## Session 3 — M2: Corpus / RAG

- **Dropped `faiss`; use an exact NumPy brute-force cosine index.** WHY: the corpus
  is tiny (tens of chunks), so faiss adds a heavy, Windows-finicky dependency for
  no benefit; NumPy is transparent, deterministic, and testable without a server.
- **L2-normalize vectors so cosine == inner product.** WHY: comparable scores
  across queries; the M5 defense can read these similarity scores directly.
- **Approximate "tokens" as whitespace words for chunking.** WHY: transparent and
  dependency-free; fine for a small curated corpus. (With 256-word chunks each
  ~100-word CTI doc is a single chunk — retrieval granularity = whole document.)
- **Embeddings go through Ollama's client with a LAZY import.** WHY: `corpus.embed`
  imports without a running server, so unit tests inject their own embeddings.
- **`retrieve()` accepts an injectable `embed_fn`.** WHY: decouples retrieval from
  Ollama so ranking/provenance are unit-tested deterministically (no server).
- **Index representation = dict {"matrix", "chunks"} persisted as vectors.npy +
  chunks.json + meta.json.** WHY: simple, inspectable, and rebuildable; injecting
  poison (M4) is just "append a vector + record and re-save."
- **Exact NumPy cosine is a reproducibility STRENGTH, not just a dependency saving.**
  WHY: brute-force search is deterministic; faiss/ANN indexes can return
  order-dependent or approximate neighbours that vary by build/threads, which would
  undermine exact run-to-run reproduction of which sources reached the agent.
- **NOTE — live embed/index/retrieve not run in the dev sandbox** (no Ollama there);
  verified chunking on real CTI + full mechanics via unit tests.
  Live smoke command for a machine with Ollama: `python scripts/02_build_corpus.py
  --test --demo "remote code execution in Apache Log4j"`.

## Session 4 — M2 corpus fixes (multi-source coverage, honest disagreement)

- **Grew the corpus to 38 docs; 17 of 21 CVEs now have ≥2 honest sources** (was 3).
  WHY: the cross-source defense can only be evaluated on multi-source CVEs; n=3 was
  too few for a credible M6 recovery / false-positive rate. 4 CVEs are deliberately
  single-source (realistic; defense cannot run there).
- **Honest sources are written to roughly match GOLD severity but DISAGREE with each
  other** (different technique emphasis, hedged vs exact severity, partial overlap;
  e.g. BlueKeep vendor hypes "wormable mass exploitation" while CISA notes limited
  observed exploitation). WHY: gives the consistency check a REAL false-positive
  challenge instead of a trivial one where honest sources are identical.
- **M6 metrics plan now includes defense FALSE-POSITIVE rate on clean multi-source
  items** (added `defense_false_positive_rate`), reported alongside recovery rate.
  WHY: a defense that "recovers" by flagging everything is useless; both sides of
  the ledger must be measured, so the corpus is built to support it.
- **Added 3 deliberately lower-profile/obscure CVEs** (CVE-2019-2725 WebLogic,
  CVE-2018-7600 Drupalgeddon2, CVE-2022-22954 VMware SSTI), study set now 21.
  WHY: **headline CVEs (Log4Shell, EternalBlue, …) bias AGAINST the steering effect**
  because the model has strong memorized priors that resist poisoning — so measured
  steering on the headline set is a CONSERVATIVE FLOOR. The obscure CVEs let us test
  whether poisoning bites harder where priors are weak.
- **Zerologon (CVE-2020-1472) CTI corrected to anchor on NVD gold 5.5 (Medium), not
  10.0.** WHY: clean sources must stay roughly consistent with gold or the BASELINE
  itself drifts, confounding the poison measurement. The real NVD-vs-operational
  severity tension is itself used as honest source disagreement. Also nudged
  ProxyLogon 9.8→9.1, Fortinet 9.8→9.1, Struts 10.0→9.8 to match exact gold.
- **Added a `corpus.min_score` cosine floor + `scripts/diagnose_retrieval.py`.** WHY:
  on a larger corpus we must confirm top-k actually DISCRIMINATES (returns the
  queried CVE, not a sweep of unrelated ones). Threshold is off by default and
  tuned after the live diagnostic shows the score distribution. Note: growing the
  corpus 9→38 chunks already makes top_k=5 selective (~13% of corpus, vs ~55% before).

## Session 4 — retrieval root-cause fix (nomic-embed-text task prefixes)

- **ROOT CAUSE of broken retrieval: missing nomic-embed-text task prefixes.** The
  live diagnostic showed rank-1 on-target 8/21 (38%), avg 4.4/5 distinct CVEs per
  query, scores clustered ~0.70–0.75, and both demo queries wrong (Log4j→Struts,
  SMB→Log4Shell). `embed.py` was embedding raw text for BOTH documents and queries.
  nomic-embed-text is trained with mandatory instruction prefixes and degrades to a
  narrow cosine band without them.
- **FIX: prefix documents with "search_document: " and queries with "search_query: ".**
  `embed_chunks` now prefixes documents, `embed_query` (new) prefixes queries, and
  `retriever.retrieve` defaults to `embed_query`. `embed_text` stays the raw
  primitive. Prefixes are module constants (nomic-specific; documented).
- **Ruled OUT the other two hypotheses with evidence, so chunking is unchanged.**
  (2) No field mismatch: docs embed the body field both sides; the query/document
  asymmetry is intended and is exactly what the prefixes address. (3) Boilerplate is
  NOT the issue: measured average pairwise content-word overlap across the 38 docs
  is only 9% (Jaccard 0.090) — docs are lexically distinct, so whole-doc vectors are
  not washed out by shared CISA/RCE phrasing. Keeping whole-doc chunking preserves a
  clean causal attribution of the improvement to the prefix fix.
- **min_score stays a SECONDARY cleanup, not the fix** (a threshold cannot repair
  wrong ordering). Revisit only after the prefix fix is confirmed live.
- **NOTE — cannot re-run the live diagnostic in the dev sandbox (no Ollama).** The
  prefix fix is verified by unit tests asserting the exact prefixed strings are sent;
  the retrieval-quality re-check must be run on a machine with Ollama.

## Session 4 — corpus homogeneity (the real root cause) + diversification rewrite

- **ROOT CAUSE (publishable methodology): naive synthetic CTI is semantically
  homogeneous.** The live embedding diagnostic on the 38-doc corpus showed mean
  cross-CVE cosine = **0.782**, with **97% of different-CVE pairs ≥0.70** and 77%
  ≥0.75; EternalBlue↔Log4Shell = 0.848; and Heartbleed (a NON-RCE info-disclosure
  doc) sat at 0.78–0.81 against RCE docs — so it is not the RCE theme but the whole
  uniform CTI-advisory writing register ("CVE-X affects PRODUCT, attacker does Y,
  CVSS Z, patch"). This collapses dense retrieval AND threatens the M5 consistency
  defense, which cannot separate sources that are all ~0.78 similar.
  **Framing for the writeup:** *naive synthetic CTI is semantically homogeneous
  (cross-CVE cosine ≈0.78), which breaks both retrieval and consistency-based
  defenses unless the corpus is deliberately diversified.*
- **The earlier prefix fix was necessary but NOT sufficient** (rank-1 38%→43%, scores
  still clustered): it corrected query/document alignment but not the underlying
  content homogeneity.
- **CHOSEN FIX: rewrite fixtures to read like real, distinct advisories** — lead with
  concrete mechanism/component/version, vary sentence structure, break the shared
  skeleton — while PRESERVING honest source disagreement and gold-consistent
  severity. Validated by the cross-CVE cosine metric, NOT by tuning to the demo
  queries. PILOT-GATED: rewrite ~5 docs (EternalBlue ×2, Log4Shell ×2, Heartbleed
  cisa), keep Struts/Drupalgeddon2 as an old-skeleton CONTROL, and only scale to 38
  if the rewritten↔rewritten cosine drops while the control holds.
- **Model A/B kept open (separates "small embedder" vs "uniform content" with
  numbers):** `diagnose_embeddings.py --model bge-m3|mxbai-embed-large` re-embeds the
  SAME docs so we can attribute the homogeneity to content vs the 137M nomic model.
- **min_score remains OFF and is NOT the fix** (cannot repair ordering or homogeneity).
- **NOTE — pilot cosine measurement must be run on a machine with Ollama** (none in
  the dev sandbox). Offline we verified: source counts unchanged (38 docs, 17 CVEs
  with ≥2 sources) and rewritten docs still state their exact NVD gold score.

## Session 4 — DECISION: switch embedder to bge-m3 (embedder was the dominant lever)

- **Switched the embedding model nomic-embed-text → bge-m3.** On the SAME corpus the
  bge-m3 A/B cut mean cross-CVE cosine 0.78 → 0.60, with pairs ≥0.75 dropping
  64% → 1% and unrelated-CVE pairs landing ~0.49–0.59 (real dynamic range). The
  Log4j demo query ranks Log4Shell #1 (failed every prior round). **Finding (for the
  writeup): embedding-model choice dominated corpus homogeneity — a small embedder
  (nomic, 137M) produced cross-CVE cosine 0.78; a stronger one (bge-m3) 0.60 on the
  same docs. Retrieval AND similarity-based defenses depend heavily on embedder
  capacity, not just content.**
- **HONESTY CAVEAT (not cleanly isolated).** The 0.60 run included the 5 pilot
  rewrites, so it conflates embedder-effect with rewrite-effect. We attribute the
  effect mainly to the embedder because the 64% → 1% collapse occurred on a corpus
  that was still 33/38 old-skeleton, but we did NOT run bge-m3 on the pre-rewrite
  corpus to separate the two with a clean control. Stated as a limitation.
- **KEEP the 5 pilot rewrites (free, strictly better docs); do NOT scale the rewrite
  to all 38.** The embedder, not the prose, was the bottleneck.
- **Prefixing is now model-aware** (`corpus/embed.py` EMBED_PREFIXES registry):
  bge-m3 uses NO prefix; nomic used search_query/search_document; sending the wrong
  prefix corrupts vectors. Swapping the embed model in config auto-selects the
  convention.
- **Embedding dim 768 → 1024.** The NumPy cosine index is dimension-agnostic
  (verified at 1024); the index MUST be rebuilt after the switch (`scripts/02`). A
  stale 768-dim index vs a 1024-dim query fails loudly on the matmul, so a missed
  rebuild cannot silently corrupt results.
- **bge-m3 is now part of the reproducibility anchor:** re-run `scripts/00_pin_models.py`
  so models.lock.json captures its exact digest; settings + lock updated to bge-m3.

## Session 5 — M3: the agent (clean data) + digest bug fix

- **BUG FIX — model digests came back null.** `resolve_model_digests` read the digest
  from `ollama show`, which returns modelfile/details but NO digest; the digest lives
  in `ollama list`. Fixed to source digests from `list()` (matched by tag, tolerating
  implicit ':latest'), keeping parameter_size/quantization from `show().details`.
  Added a guard in `00_pin_models.py` that aborts if any digest is still null, so the
  reproducibility anchor can never be silently committed empty. Verified by an offline
  test with a stub client (`ollama list` has digests, `show` does not).
- **Retrieval query = the CVE's NVD description.** WHY: it's the exact query form
  validated at 90% rank-1 on-target in diagnose_retrieval; the agent asks "what is
  this CVE" so the description is the natural query.
- **ATT&CK validation is POST-HOC, not catalog-in-prompt.** The enterprise matrix is
  ~700 techniques and will not fit a small model's context, so the model proposes IDs
  (from training + CTI) and `attack_mapper.validate_ids` keeps only IDs present in the
  catalog. WHY: constrains the label space without a huge prompt; hallucinated IDs are
  dropped and reported. Measured effect is CHANGE under poisoning, not absolute accuracy.
- **Structured JSON outputs via Ollama `format=json` + a tolerant parser.** WHY:
  deterministic parsing of techniques/severity; `llm._loads` salvages a JSON object if
  the model wraps it in stray text.
- **Severity scorer framed around DEFLATION** (per the threat model: make a critical CVE
  look low) — the prompt is neutral but the evaluation will measure downward drift.
- **`pipeline.run_item` takes an optional `defense(chunks)` hook (provisional for M5)**
  returning {kept_chunks, ...}; the agent reasons over the kept set. WHY: same code path
  for clean/poison/defended so the agent logic is identical across conditions. The hook
  signature may tighten in M5.
- **FLAG for M4/M5 (recorded per request): avg distinct CVEs/query is still ~4.1** —
  rank-1 is strong (90%) but the retrieved tail is mixed. Acceptable for M3/M4, but in
  M4 we MUST verify the poisoned source for CVE-X actually lands in the retrieved top-k
  when querying CVE-X (else the attack cannot take effect), and in M5 the consistency
  defense must cope with a mixed-CVE retrieved set, not assume all chunks concern one CVE.
- **NOTE — 2-CVE smoke test must be run on a machine with Ollama** (none in the dev
  sandbox). Agent logic is verified by 10 offline unit tests (prompt rendering, ID
  validation, JSON salvage, scorer coercion, pipeline shape + defense hook).

## Session 5 — M3 instrument fix: hallucinated ATT&CK names/IDs

- **BUG (caught at smoke): the validator passed real IDs paired with INVENTED names,
  and sometimes wrong IDs for the concept** (e.g. T1046 labelled "Web Shell"; T1027
  labelled "Remote Code Execution"). Severity was perfect; only ATT&CK was affected.
  Free-form ID recall by a small model is unreliable.
- **FIX #1 (applied): never trust model-supplied technique NAMES.** For every valid ID
  the name is OVERWRITTEN with the canonical catalog name. Additionally we record a
  CONCEPT MISMATCH (token-Jaccard < 0.34 between the model's name and the canonical
  name) as a hallucination signal — the model likely meant a different technique than
  the ID it emitted. `map_to_attack` now returns techniques (canonical names), dropped
  (invalid IDs), and mismatches; the baseline reports counts of both. Verified the
  heuristic flags all four reported cases and tolerates abbreviation differences.
- **OPEN DECISION #2 (proposed, awaiting approval): switch to catalog-GROUNDED ATT&CK
  mapping** — model emits behavioral descriptions (NL), we map to technique IDs via
  bge-m3 embedding similarity over the catalog's name+description. WHY: it removes the
  model's unreliable ID recall entirely (IDs always match the described concept) and is
  more defensible methodology. Trigger to decide: the mismatch/dropped counts from the
  #1-fixed smoke run quantify how bad free-form IDs are. Trade-off: adds a technique
  index + a mapping hyperparameter (top-k/threshold). Not built yet.

## Session 5 — M3 methodology: catalog-grounded ATT&CK mapping (DECISION #2 approved)

- **FINDING + METHODOLOGY CHOICE: llama3:8b mismatched ATT&CK ID/concept ~75% on clean
  data (6/8 techniques — correct intent, wrong T-code, e.g. meant "exploit public-facing
  app" but emitted T1027/T1204). We therefore map via catalog-similarity over official
  technique descriptions rather than model-recalled IDs.**
- **New pipeline:** the model emits plain-language attacker BEHAVIORS (no IDs/names);
  each behavior is embedded (bge-m3) and matched against the ~700 official ATT&CK
  techniques ("name. description" embedded once at index-build time, `data/processed/
  attack_index`). Top-k per behavior above an optional cosine floor, aggregated (best
  score per technique), capped at `max_techniques`. Canonical names by construction; no
  hallucinated or wrong-for-concept IDs possible.
- **Free-form IDs and the name-overwrite/mismatch machinery (fix #1) are now REMOVED**
  from the prediction path — superseded by grounding.
- **Severity scorer unchanged** (3 clean runs dead-on gold; not touched).
- **GATE before trusting grounded mapping (`scripts/diagnose_attack_catalog.py`):** the
  catalog is itself a retrieval-homogeneity risk (700 techniques, similar language) — the
  same problem we spent six rounds fixing for the CTI corpus. The diagnostic reports
  cross-technique cosine stats + 5 labeled probes (known-correct technique must land in
  top-k with score separation). DO NOT proceed to the smoke / M4 unless it discriminates;
  if not, fall back to keyword-hybrid or a curated technique subset.
- **Likely tuning pending the gate:** with top_k=2 and no min_score, each behavior also
  pulls a weak second technique; the catalog diagnostic + smoke will tell us whether to
  set top_k=1 or a min_score floor to drop weak matches.
- **NOTE — neither the catalog diagnostic nor the smoke can run in the dev sandbox**
  (no Ollama). Grounded-mapping logic is verified by offline unit tests (behavior->
  technique grounding, canonical names, min_score floor, dedup/best-score); the catalog
  diagnostic was offline-traced for shape/sub-technique-match correctness.

## Session 5 — M3 grounded-mapping FAILED gate -> abstraction-gap fix (effect/mechanism)

- **CATALOG GATE FAILED — root cause is an ABSTRACTION GAP, not catalog homogeneity**
  (catalog mean cosine 0.582, only 3% of pairs >=0.7). The agent described low-level
  MECHANISM ("crafted SMB packet, kernel code execution"; "JNDI lookup over LDAP") but
  ATT&CK technique descriptions are higher-level TACTIC prose, so bge-m3 matched surface
  vocabulary: SMB->T1210 ranked 16, JNDI->T1190 ranked 24, and wrong winners (SMB Admin
  Shares, Kernel Modules, RDP Hijacking) sat in UNRELATED tactics. Decisive evidence:
  T1190 "Exploit Public-Facing Application" shares ZERO content tokens with the Log4Shell
  behavior, so the correct technique cannot compete on surface terms.
- **REJECTED the naive query-lift prompt (it leaked the answers).** Handing the model
  near-verbatim ATT&CK names ("exploitation of a remote service", "command and scripting
  interpreter execution") would pass the gate on pre-loaded vocabulary, not reasoning,
  AND could make the agent artificially poison-resistant by collapsing it into a canned
  phrase set — understating the effect we measure.
- **FIX (leak-free query-side lift): the model emits, per behavior, `effect` (its OWN
  words: what the attacker achieves + against what target) and `mechanism` (the how).**
  We MAP on `effect` (the model's own abstraction lift, which meets ATT&CK's tactical
  level) and KEEP `mechanism` for transparency and CVE-distinguishability. The prompt
  gives only field definitions — NO ATT&CK names and NO worked examples — and asks for
  detail "specific to THIS vulnerability" to avoid one-layer-up homogeneity. Two RCE CVEs
  mapping to the same technique is correct; distinguishability lives in `mechanism`.
- **ANTI-LEAKAGE GATE:** the authoritative check is the AGENT's real emitted text
  (`scripts/03_run_baseline.py --test` prints effect+mechanism for EternalBlue = the SMB
  case and Log4Shell = the JNDI case), so we can verify the model is abstracting, not
  parroting. `diagnose_attack_catalog.py` probes are now neutral effect-level proxies
  (no ATT&CK names), flagged as a controlled supplement. Stricter bar: >=4/5 probes
  correct in top-3 AND positive gap on the SMB and JNDI cases specifically.
- **CONTINGENCY (not built): if clean (b) still can't separate SMB/JNDI, stack (c) as a
  SOFT tactic prior** (down-weight other tactics, never hard-exclude, since techniques
  are multi-tactic and a wrong tactic would catastrophically drop the correct one). Will
  propose the design before coding.

## Session 5 — M3 cross-CVE contamination fix + (c) soft-tactic-prior proposal

- **CONTAMINATION (priority, FIXED): the agent was blending a DIFFERENT CVE's source into
  a CVE's analysis** — e.g. Log4Shell's behaviors contained F5 BIG-IP (CVE-2022-1388)
  web-shell text retrieved at rank 3 (0.554). This is the retrieval-tail risk made real;
  left unfixed it makes the M4 poison signal uninterpretable.
- **FIX: `corpus.restrict_to_cve` (default true) — keep only retrieved chunks whose
  `mentions_cves` includes the target CVE.** Chosen over a min_score floor because it is
  an oracle-clean guarantee, not a fragile per-CVE threshold (the 0.554 F5 chunk vs a
  ~0.60 on-target chunk is too thin a margin to threshold safely), and it matches both
  the threat model (an analyst reads sources ABOUT the CVE) and M4 (the poison targets and
  so mentions the CVE, so it still competes among that CVE's honest sources; embedding
  similarity ranks within them). Implemented in retriever.retrieve (rank-all -> filter to
  CVE -> top_k). Proven offline on the real corpus: Log4Shell and EternalBlue each now see
  only their own 2 sources, NONE other-CVE.
- **MAPPING still fails on the REAL agent output (not just the proxy): EternalBlue ->
  T1547.006 Kernel Modules (surface "kernel"), Log4Shell -> T1674/T1556 — both wrong, T1210
  and T1190 absent.** Two query-side attempts (prefixes, effect/mechanism) were not enough;
  escalating to (c).
- **(c) PROPOSED (awaiting approval, NOT coded): SOFT tactic prior, stacked on (b).**
  Stage 1: fold a `tactic` field into the behavior JSON (model classifies into 1 of 12
  ATT&CK tactics — coarse, reliable, only feeds a soft prior). Stage 2:
  `adjusted(t,b) = cosine(effect_b, t) + α·1[tactics(t) ∩ tactic(b) ≠ ∅]`, with
  α = `attack_mapping.tactic_bonus` default 0.10 (chosen because observed wrong-vs-correct
  gaps were ≈ −0.05, so +0.10 to the correct-tactic technique flips the sign). NEVER a
  penalty/exclusion — non-matching techniques keep raw cosine, so a mis-tagged tactic
  cannot drop the correct technique. Uses the `tactics` already in the attack index.
- **LESSON (methodology): the proxy probes "passed" while the real agent output FAILED —
  hand-written proxies are not trustworthy gates; the authoritative gate is the agent's
  real emitted text (03 --test).**

## Session 5 — M3 (c) soft tactic prior IMPLEMENTED

- **(c) implemented as approved:** the behavior JSON now carries a `tactic` field (UP TO
  TWO of the 12 ATT&CK tactics, classified in the SAME LLM call from names+one-line
  defs). Mapping score is `adjusted = cosine + alpha * [behavior tactics ∩ technique
  tactics]`, `alpha = attack_mapping.tactic_bonus` (default 0.10), ADDITIVE ONLY.
- **Critical design choice: the bonus is applied over the FULL catalog, then top-k is
  taken** — NOT top-k-by-cosine then bonus. WHY: the correct technique was buried at
  rank 16 (T1210) / 24 (T1190) by surface vocabulary; if we only bonus the cosine top-k
  it would never be a candidate and the prior couldn't rescue it. Over the full catalog,
  a correct-tactic technique deep by cosine can be lifted.
- **Soft / never-exclude guarantee (tested):** a technique in a non-matching tactic keeps
  its raw cosine and still competes, so a mis-tagged tactic cannot drop the correct
  technique (test_tactic_prior_never_excludes_on_wrong_tag). Tactic names normalized to
  catalog phases ("Lateral Movement" -> "lateral-movement"); unknown tactics dropped,
  capped at 2.
- **Per-behavior diagnostic output** (03 --test prints, per behavior: effect, mechanism,
  predicted tactic(s), and each candidate technique's cosine -> adjusted score with a
  +tactic marker) so a miss is attributable to stage-1 (wrong tactic tag) vs stage-2
  (alpha too small). Verified by 59 offline unit tests; live gate runs on a machine with
  Ollama.

## Session 5 — M3 SCOPING DECISION: severity primary, ATT&CK mapping secondary

- **FINDING (full evidence chain): reliable fine-grained ATT&CK mapping is not
  achievable with a small local model (llama3:8b) in this setup.**
  1. *Raw model-recalled IDs:* ~75% ID/concept mismatch on clean data (correct intent,
     wrong T-code — e.g. meant "RCE/exploit public-facing app" but emitted T1027/T1204).
  2. *Catalog-grounded mapping (model emits behavior -> bge-m3 similarity over official
     technique descriptions):* fixes hallucinated IDs but fails on an ABSTRACTION GAP —
     the model speaks low-level mechanism, ATT&CK speaks tactic, so bge-m3 surface-matches
     (EternalBlue -> "Kernel Modules"; Log4Shell -> process-injection; T1190 shares ZERO
     tokens with the Log4Shell behavior). Catalog itself is fine (mean cosine 0.582).
  3. *Soft tactic prior (behavior -> 1-2 tactics, +0.10 to matching-tactic techniques,
     never exclude):* fails at STAGE 1 — the model misclassifies the tactic (Log4Shell's
     behaviors tagged across execution/initial-access/credential-access/exfiltration; the
     winner T1212 rode a WRONG tag). The prior amplifies tactic-classification noise.
  Conclusion: after grounding + tactic prior, the bottleneck is the model's own
  tactic/technique classification, which is unreliable; further mechanism tweaks are not
  worth it.
- **DECISION: severity is the PRIMARY steering axis; ATT&CK mapping is SECONDARY /
  best-effort, reported WITH its unreliability as a documented finding.** Severity is
  exact vs NVD gold and was dead-on on 5/5 clean runs; it is where steering can be
  measured cleanly.
- **Mapper + tactic prior are KEPT (honest best-effort) but FROZEN** at tactic_bonus=0.10;
  we stop tuning the mapping.
- **Severity steering channel verified (code):** `cve_scorer.score_cve(cve, chunks)` ->
  `prompts.render_cve_severity` fills the `{context}` block with every retrieved source's
  text, and the pipeline feeds it the CVE-restricted retrieved chunks. So poison in a
  CVE's CTI reaches the severity prompt. DIAL: the prompt also includes the NVD
  description (a prior the poison must overcome) — the obscure CVEs (weak priors) are the
  cleaner steerability test bed; if M4 shows the description over-anchors, shrink it to a
  bare identifier.
- **METRICS PLAN REFRAMED (M4-M6):**
  - PRIMARY: severity_drift (clean vs poisoned vs NVD gold); severity_asr (deflation past
    a margin); defense_recovery; defense_false_positive_rate on clean multi-source CVEs.
  - SECONDARY (caveated): mapping_change_rate — does poison PERTURB the mapped technique
    set at all (NOT accuracy vs a gold technique).
  - DROPPED: the curated CVE->technique gold set and its Cohen's-kappa inter-annotator
    step are no longer needed (mapping is perturbation-only, no technique ground truth).
    This removes the most subjective workstream; severity gold (NVD CVSS) carries the study.

## Session 5 — INSTRUMENT BUG: severity scorer was fed the gold answer

- **The first steerability probe showed NO movement and BYTE-IDENTICAL clean/poisoned
  rationales** ("RCE via crafted SOAP request"). Rendering the exact scorer prompt offline
  found the cause: **the stored NVD `description` literally contains the CVSS score and
  vector** — e.g. for CVE-2019-2725: "... Base Score 9.8 ... CVSS:3.0/AV:N/AC:L/PR:N/
  UI:N/S:U/C:H/I:H/A:H." The model copies the pasted-in gold answer, so it ignores the CTI
  entirely. The system prompt even said "base your assessment on the CVE description."
  This is an INSTRUMENT bug, not a robustness finding.
- **FIX (proposed; validated via the 3-way probe before wiring into the pipeline):** feed
  the model a LEAK-FREE CVE identifier ("CVE-id in <product>", no CVSS/severity words)
  instead of the full NVD description, and change the system instruction to base severity
  on the CTI context. NVD CVSS stays as the GOLD comparison label — it is just no longer an
  input. Offline-verified the neutral identifier has zero CVSS/severity leakage on the 3
  obscure CVEs (VMware safely falls back to id-only).
- **3-way sensitivity probe (scripts/probe_severity_sensitivity.py)** scores honest /
  honest+emphasizing / honest+deflating, with `--neutral` toggling the fix. Decision rule
  (before M4): FULL mode should show a==b==c (confirms the bug); NEUTRAL mode should show
  clean ~= gold derived from honest CTI AND emphasizing > deflating (real steerability).
  NOTE: live run needs Ollama (not in dev sandbox); data assembly + neutral extraction
  offline-traced.

## Session 5 — severity steerability: isolating cause (CTI vs memorized prior)

- **Neutralizing the NVD description did NOT make the score move** (stayed 9.8 across
  honest/emphasizing/deflating). Test 1 (offline CTI audit) found WHY in part: BOTH honest
  WebLogic fixtures assert "critical", and the vendor source contains "crafted SOAP
  request / RCE / unauthenticated" verbatim. So (a) the rationale phrasing comes from the
  honest CTI, not necessarily memory, and (b) the probe was MIS-DESIGNED — clean is already
  at the critical ceiling (honest says critical), so emphasizing cannot move up and
  deflating is 1 poison vs 2 honest "critical" assertions (corroboration, a harder test).
- **Two live isolation tests built (scripts/probe_severity_isolation.py):** TEST 2 scores a
  real CVE with neutral id and EMPTY CTI (if ~9.8 from nothing -> memorized prior in the
  weights); TEST 3 uses a fully FICTIONAL CVE (CVE-2099-0001 / Nimbus Cache Server) with a
  severity-NEUTRAL base source, scored base / +emphasizing / +deflating (if emphasizing >>
  deflating -> the scorer CAN read CTI severity).
- **Likely consequence (to confirm with the run): build M4 on SYNTHETIC CVEs** whose only
  information source is CTI we control — this removes memorized priors AND the NVD-answer
  leak AND lets us control honest-vs-poison corroboration ("N honest vs M poison"). For
  synthetic CVEs the reference severity is the honest-source consensus we design (no NVD
  gold). Tradeoff: loses NVD-exact gold; mitigate by using realistic CTI prose and
  optionally reporting a secondary, caveated real-CVE arm. Honest fixtures for any real-CVE
  arm would also need softening (they currently assert "critical" outright).

## Session 6 — M4: severity poisoning on the synthetic CVE arm

- **Severity steerability CONFIRMED (isolation probe):** synthetic CVE, emphasizing 9.8 vs
  deflating 4.3 (spread 5.5); TEST 2 gave a generic 7.5 from empty CTI (NOT memorized
  recall). The real-CVE failures were (a) NVD description leaking the CVSS answer and (b)
  our honest fixtures asserting "critical" — both things we control. Severity axis is sound.
- **M4 built on SYNTHETIC CVEs** (data/synthetic/synthetic_cves.json): 4 fictional CVEs,
  bidirectional — 2 CRITICAL (deflation targets), 2 LOW/MEDIUM (inflation targets). Honest
  sources (>=2 each, with source disagreement) establish severity through FACTUAL
  mechanism/impact/exposure ONLY; a unit test guards that none contain
  "critical"/"cvss"/"base score"/"severe" (prevents the answer-key bug recurring).
- **Reference 'gold' = the honest-consensus severity by construction** (designed into each
  synthetic CVE), replacing NVD gold for this arm. WHY: real CVEs are prior-contaminated and
  leak the score; synthetic isolates the CTI->severity mechanism with a controllable reference.
- **Poison module (poison/payloads.py): single injected source, BOTH directions** —
  craft_deflation (hide a real critical) / craft_inflation (manufacture a false emergency),
  in a realistic vendor re-assessment register (the register that moved the WebLogic probe).
  The CVE is presented to the scorer by NEUTRAL identifier only (no description, no CVSS).
- **Runner (scripts/04_run_poison.py):** clean (honest only) vs poisoned (honest + 1 poison)
  per CVE; before/after table with consensus/clean/poisoned/delta/success + poisoned rationale.
- **REAL-CVE arm deferred** (external validity, harder/prior-contaminated condition) until
  the real-CVE honest fixtures are rewritten to remove "critical"/CVSS.
- **NOTE — live run needs Ollama; offline-traced assembly + 65 unit tests. Stopping for the
  before/after demo on 2-3 CVEs before scaling the synthetic set to 6-8.**

## Session 6 — M4 first results: deflation/inflation asymmetry + scaling

- **FIRST RESULT (3-CVE demo): clean tracks consensus (deflate ~9.5/9.8, inflate ~4.0) and
  all 3 steered.** But two things to investigate, now instrumented:
  - **ASYMMETRY (candidate finding): easy to INFLATE, hard to DEFLATE.** Inflation was total
    (-> 9.8, rationale fully adopted the poison). Deflation was partial (-> 7.5, still HIGH,
    not the LOW the poison claimed) and the rationale still described a severe unauth RCE. The
    model resists hiding a real critical — the safety-relevant direction.
  - **INCOHERENCE (score/rationale coupling): in deflation the number (7.5) contradicted the
    model's own severe rationale.** Hypothesis: with format=json the model produces score +
    rationale somewhat independently — under conflicting sources it HEDGES the number toward
    the middle while the prose follows the majority. To diagnose without running: the runner
    now prints the FULL clean->poisoned rationale for every CVE so adoption-vs-score-movement
    is visible. (A causal test would be a reason-then-score prompt variant; not done — would
    change the frozen instrument; propose if wanted.)
- **CONTROL added (length/specificity): poison payloads trimmed to ~60 words (deflation 59,
  inflation 60), within the honest-source range [41,77] (mean 57) and EQUAL to each other** —
  so any deflation-vs-inflation asymmetry is content/direction, not the poison being longer or
  more vivid. Enforced by a unit test.
- **Synthetic set SCALED to 8** (4 deflate CRITICAL/9.6-9.8, 4 inflate MEDIUM-LOW/3.3-5.4),
  keeping the severity spread, leak guard (no "critical"/cvss/severe), and honest source
  disagreement. Runner now reports per-direction success rate + mean drift, and the full
  rationale comparison for all CVEs.

## Session 6 — M4 score-quantization diagnosis

- **Scaled run gave SUSPICIOUSLY UNIFORM scores: byte-identical per direction across all 8
  CVEs (deflate 9.8->7.5, inflate 4.3->9.8, 8/8, zero variance).** Rationales differ per CVE
  (model reads different CTI) but scores collapse to canonical CVSS anchors (9.8/7.5/4.3).
- **Task 1 answered from CODE: our scorer does NOT quantize.** cve_scorer.score_cve does
  `base_score = float(model_output)` — pure passthrough, no rounding/snapping; `vector` and
  full `raw` model JSON are preserved (already in the saved jsonl). So the discreteness is the
  MODEL emitting standard CVSS anchors under temp=0 (it behaves like a CVSS calculator: pick
  the canonical vector for a severity class -> its textbook score; deterministic at temp=0 ->
  same anchor for same class -> uniformity across different CVEs of that class).
- **Tasks 2 & 3 probe built (scripts/probe_score_quantization.py):** prints RAW base_score +
  vector; compares different-consensus CVEs (0001@9.5 vs 0002@9.8 — do they differ?); and
  re-scores at temperature 0.3 with distinct seeds to see whether scores spread or stay locked.
- **Reporting framing (to confirm with the probe):** if temp>0 spreads -> the temp=0 uniformity
  is an anchor-snapping artifact; report "mean drift ~-2.3 deflate / ~+5.5 inflate, scorer
  emits discrete CVSS anchors" (NOT "every attack moved by exactly X"). If locked -> the scorer
  is genuinely coarse; report at the BAND/anchor level (categorical), not implied continuous
  precision. Either way, "exactly X every time" is not how we'll state it.
- **NOTE — probe needs Ollama (not in dev sandbox); assembly offline-traced.**

## Session 6 — M4 LOCKED at band level

- **FINDING:** *The local model (llama3:8b) emits canonical CVSS base scores with
  hallucinated/malformed CVSS vectors — it imitates CVSS output format without performing
  CVSS computation, and cannot resolve magnitude (different-consensus criticals both score
  9.8). Severity is therefore evaluated at the band level, which is stable under sampling.
  This is itself a finding: small local models are crude severity instruments, so poisoning
  manifests as categorical band-shifts.*
  - Evidence: saved vectors are garbage ("CVSS:3.1/AV:NAC:CWE:78", v2 "Au:N" mixed into 3.1,
    CWE codes that aren't CVSS fields); temp=0.3 across 5 seeds returned 9.8 every time
    (range 0.0) for both CVE-0001@9.5 and CVE-0002@9.8; band was consistently CRITICAL.
- **PRIMARY metric = severity BAND shift** (CRITICAL/HIGH/MEDIUM/LOW); attack success = band
  moved in the attacker's direction. Implemented in metrics.py (score_to_band, band_ordinal,
  band_shift, severity_band_asr). Raw 0-10 score kept in data, reported ONLY as instrument
  crudeness evidence; CVSS vector DROPPED (unusable).
- **M4 result restated at band level:** deflation CRITICAL->HIGH (one-band drop, never reached
  LOW); inflation MEDIUM/LOW->CRITICAL (two-band jump). The inflation>deflation asymmetry
  HOLDS and is starker at band level (2 bands vs 1).
- **(d) band-vs-rationale spot-check (assessed from the reported run, not re-run):** INFLATION
  — band CRITICAL is fully consistent with the rationale, which adopts the poison's false
  urgency ("unauthenticated, no user interaction"). DEFLATION — band HIGH is consistent with
  the rationale STILL describing a severe unauthenticated RCE; the poison achieved a one-band
  nudge, not a reasoning reversal, and HIGH remains in the "severe" range (the model did not
  follow the poison down to LOW). So the band tracks the rationale's described severity in
  both directions; the earlier numeric "incoherence" (7.5 vs severe prose) dissolves at band
  level (HIGH == severe). Reporting at the band level removes the apparent contradiction.

## Session 6 — M5: cross-source consistency defense (built, pre-eval)

- **Defense (defense/consistency.py): score each retrieved source ALONE -> per-source band;
  flag any source whose solo band is >= `band_outlier_distance` (default 2) bands from the
  consensus; exclude it and re-score.** WHY band-distance 2: honest sources disagree by ~1
  band (by corpus design), but a deflation poison reads LOW vs a CRITICAL consensus (3 bands)
  and an inflation poison reads CRITICAL vs MEDIUM (2 bands) — so 2 catches the poison while
  tolerating honest one-band wobble. Exclusion only; training-free.
- **Both sides of the ledger (scripts/05_run_defense.py):** RECOVERY on poisoned input
  (clean->poisoned->defended band; success = defended band restored to clean band) AND
  FALSE-POSITIVE on clean input (does the check flag an honest source when no poison is
  present?). The poison carries the same source tag as honest ones; detection is measured by
  object identity (measurement only — the defense uses band outliers, never that).
- **Metrics (metrics.py): defense_band_recovery, defense_false_positive_rate** — both pure,
  unit-tested. Defense logic unit-tested offline with a stub scorer (deflation+inflation
  poison flagged; honest 1-band disagreement NOT flagged = no false positive).
- **NOTE — live M5 run needs Ollama (~8 score calls/CVE); offline-traced + 75 unit tests.
  STOPPING before the full evaluation per instruction.**

## Session 6 — M5 results + precision/recall floor

- **First M5 run: 6/8 poison detection, 0.75 band recovery, 0.00 false-positive rate.** Zero
  FP on deliberately-disagreeing honest sources is the key win — the defense separates honest
  one-band wobble from poison without crying wolf. Consensus is outlier-robust (majority/mode,
  median tie-break — never a poison-shiftable mean/sum).
- **The 2 misses are both DEFLATION (0005, 0006); candidate finding = a precision/recall
  FLOOR.** A deflation poison whose solo band is only 1 band below the CRITICAL consensus
  (HIGH) hides inside the SAME one-band tolerance we must allow honest sources. You cannot
  catch a 1-band-out poison at band_outlier_distance=2 without also flagging honest one-band
  disagreement (FP). Whether a given deflation poison lands 1 vs >=2 bands out depends on how
  the model scores the poison source IN ISOLATION (itself noisy — the crudeness finding).
- **scripts/inspect_defense.py recomputes everything OFFLINE from the saved defense.jsonl**
  (the flag decision is pure arithmetic on per-source bands): prints per-CVE per-source bands
  (poison = last) + consensus, and a band_outlier_distance sweep (1/2/3) giving per-direction
  detection AND clean FP rate — i.e. the precision/recall curve, no model re-run.
- **Structural asymmetry (to confirm on real data): inflation is easy to catch, deflation can
  hide.** Inflation poison must claim CRITICAL, which is 2-3 bands above a LOW/MEDIUM consensus
  -> always a large outlier -> caught. Deflation poison against a CRITICAL consensus is only a
  large outlier if it reads LOW/MEDIUM alone; if it reads HIGH (1 band) it hides. This is the
  headline defense finding if the per-source bands confirm it.

## Session 6 — M5 CONSENSUS BASELINE FLAW (corrected mechanism)

- **The camouflage hypothesis was WRONG.** Real per-source bands: 0005/0006 poison scored
  MEDIUM-alone (not HIGH). They were missed because the CONSENSUS was HIGH (not CRITICAL):
  the two honest sources DISAGREE solo (['CRITICAL','HIGH']) and the poison (MEDIUM) is in the
  vote, so the median of [CRITICAL,HIGH,MEDIUM] = HIGH -> MEDIUM poison is only 1 band out ->
  missed. 0001/0002 honest AGREE (['CRITICAL','CRITICAL']) -> consensus CRITICAL -> same MEDIUM
  poison is 2 bands out -> caught. **Detection failure is driven by HONEST-SOURCE DISAGREEMENT
  weakening the consensus baseline, not by the poison being partial.**
- **TWO compounding flaws in the current consensus:**
  (i) SOLO scoring loses corroborating context — an honest source reads HIGH alone but
      CRITICAL when scored jointly with the other honest source (the model is more confident
      with corroboration). So the vote-of-solo-bands UNDERESTIMATES vs the clean JOINT band
      (0005 clean joint = CRITICAL, but vote-consensus = HIGH).
  (ii) The consensus is computed INCLUDING the poison, so the poison drags its own baseline
      toward itself (the MEDIUM poison pulls the median down to HIGH), shrinking its distance.
- **Per-direction (corrected): inflation 4/4 (honest agree, poison 2-3 bands out); deflation
  2/4 (the 2 misses are the disagreeing-honest CVEs).** Report inflation-easy/deflation-hard
  with the CORRECTED mechanism: deflation hides when honest sources DISAGREE, not because the
  poison is partial.
- **FIX PROPOSED (awaiting approval; see chat):** measure each source against the leave-one-out
  JOINT band of the OTHER sources (excludes the poison from its own baseline + preserves
  context), which requires >=3 honest sources so a removal retains corroboration. The sweep
  numbers are provisional until the baseline is fixed.

## Session 6 — M5 redesign: leave-one-out joint scoring (APPROVED, Option 1)

- **defense/consistency.py rewritten to LEAVE-ONE-OUT joint scoring.** influence(s) =
  |joint_band(all) - joint_band(all without s)|; flag sources with influence >= min_influence;
  corrected band = joint of the others once the outlier is removed. This fixes both prior
  flaws: the baseline is a context-preserving JOINT band (not a vote of isolated bands) and a
  source is judged against the OTHERS (the poison is excluded from its own baseline). Abstains
  at < 3 sources (a removal would leave a single source = context loss returns).
- **Added a 3rd genuinely-independent honest source to all 8 synthetic CVEs** (own emphasis,
  realistic disagreement, NOT corroborating copies; leak-free; length-controlled, 38-50w within
  the honest range). Verified offline: 3 distinct sources/CVE, 0 leaks, both directions intact.
- **COUPLING FLAGGED — this changes M4 too.** 04_run_poison reads honest_sources, so the attack
  now faces 3 honest sources, not 2. The single poison may be DILUTED (3:1 corroboration) and
  move the band less, or not at all. M4 must be re-run; if the attack weakens, that is itself a
  clean finding ("a single source is harder to push past stronger corroboration"), and it ties
  attack and defense together (the defense works because corroboration dilutes the poison).
- **config: defense.band_outlier_distance -> defense.min_influence (default 1).** Runner/inspector
  updated to the influence shape; inspect_defense.py sweeps min_influence (1/2/3) offline.
- **Verified offline:** LOO trace on 0005 (previously missed) now catches the poison
  (influences [0,0,0,1], corrected CRITICAL) with FP=0; 76 unit tests pass (flag/keep/abstain/
  no-FP-on-disagreeing-honest/higher-threshold-misses-1-band). Live re-run needed for real bands.

## Session 6 — M5 detection vs RECOVERY (8/8 caught, 4/8 recovered)

- **Live run: 8/8 detection BUT only 4/8 RECOVERY.** The defense removed every poison but
  restored the clean band on only 4 CVEs. The 4 failures (0003/0004/0005/0006) are exactly the
  CVEs where honest sources also have leave-one-out influence (0003 [0,1,1], 0004 [1,1,1],
  0005/0006 [1,0,0]).
- **DIAGNOSIS = recovery MATH bug, NOT fixtures.** Two parts:
  (1) corrected-band rule `corrected = flagged[0]['others_band'] if len(flagged)==1 else j_all`
      falls back to the POISONED j_all whenever >1 source is flagged. The 4 failures are the
      multi-flag CVEs.
  (2) honest sources get flagged because influence = abs(...) is DIRECTIONLESS: removing the
      poison moves the joint UP toward clean (restoring) while removing a load-bearing honest
      moves it DOWN, further from clean (degrading) — both score |influence| >= 1.
  Crucially, `poison's others_band == joint(honest) == clean_band BY CONSTRUCTION`, so
  REMOVING ONLY THE POISON recovers the clean band every time (inspector: remove-poison-only
  8/8 vs current 4/8). honest-only reads CLEAN; the fixtures are fine.
- **CONFIRMED M4 finding (#2): a 3rd honest source HALVES the inflation attack** — inflation
  weakened from MEDIUM->CRITICAL (2 bands, 2-source corpus) to MEDIUM->HIGH (1 band, 3-source).
  Deflation stayed CRITICAL->HIGH (1 band). Corroboration partially resists single-source
  poison; the recovery failures are now ALL 1-band attacks.
- **FIX (proposed, not yet implemented — diagnose-first per instruction):** (i) recovery rule
  = remove ONLY the single identified poison and report joint(others); (ii) identify the single
  poison robustly, not by directionless abs-influence — e.g. the source whose removal makes the
  remaining set INTERNALLY CONSISTENT (a stable consensus), which under the single-poison threat
  model is the honest set. inspect_defense.py [3] now shows current-rule vs remove-poison-only
  recovery from saved data (no re-run).

## Session 6 — M5 identification-rule simulation (pick on data, offline)

- **inspect_defense.py [4] simulates 3 identification rules from the SAVED per-source bands**
  (poison_report + clean_report carry every source's others_band + influence), so detection /
  recovery / FP are recomputed with NO model re-run:
  1. CURRENT (abs-influence >=1, j_all fallback) — the broken baseline.
  2. DIRECTIONAL — poison = the unique MINORITY-direction mover (restorer vs the load-bearing
     crowd). Resolves CVEs with >=2 influential honest, but a 1-honest-vs-poison TIE it cannot.
  3. INTERNAL-CONSISTENCY — poison = the source whose removal leaves a >=3-source INTERNALLY
     CONSISTENT (stable) set; declares NO POISON otherwise.
- **Rule 3 is FALSE-POSITIVE-FREE BY CONSTRUCTION** (the property the experiment demanded): on
  clean 3-source input, removing any source leaves only 2 sources, which can never be a
  ">=3-source consistent rest", so it CANNOT name an honest source as poison even when honest
  sources disagree by a band. Its recovery == the number of CVEs whose honest set is internally
  consistent (printed per-CVE). Validated on fabricated data: Rule1 1/3, Rule2 2/3, Rule3 3/3
  recovery, all FP 0/3.
- **Decision pending the live inspect [4] on the real defense.jsonl** (no re-run; user near usage
  limit). Winning rule approved -> implemented once.

## Session 6 — M5 FINAL defense (Rule 3 implemented)

- **FINAL defense = leave-one-out INTERNAL-CONSISTENCY identification + remove-single-poison
  recovery** (defense/consistency.py). The poison = the single source whose removal leaves a
  >= min_consensus (3) internally-consistent set (joint band stable to dropping any member);
  corrected band = joint(that rest) = joint(honest). Declares NO POISON if the full set is
  already consistent or no unique such source exists.
- **Rule 3 chosen on DATA (offline inspect [4] on the real run):** detection 8/8, recovery 8/8,
  FP 0/8; all 8 honest sets internally consistent. Rule 2 (directional) only 6/8 (fails the
  1-honest-vs-1-poison tie on 0005/0006); Rule 1 (current) 4/8 recovery.
- **PRECONDITION / LIMITATION (documented in code): detection needs >= 4 total sources** (a
  consistent rest needs >= 3, so >= 3 must remain after removing the suspect). With < 4 the
  check abstains. This is why FP = 0 on clean input BY CONSTRUCTION: clean 3-honest input,
  removing one leaves 2 (< 3), so no honest source can ever be named the poison even when honest
  sources disagree by a band. A genuine threat-model limit, stated plainly.
- **RECOVERY CEILING = honest-set internal consistency** (8/8 here). If the honest sources did
  not read a stable consensus, the corrected band could be wrong; on the synthetic set they do.
- **Verified: 75 unit tests pass; faithful-stub end-to-end trace = 8/8 / 8/8 / 0 FP.** ONE live
  run of scripts/05_run_defense.py remains to confirm the real model matches (the run that
  validates the actual consistency checks, not the offline assumptions). After that, M6 =
  assemble results tables from the jsonl on disk, NO further model runs.

## Session 7 — M6: RESULTS.md assembled from saved jsonl (study complete)

- **scripts/06_evaluate.py generates RESULTS.md from the saved experiment jsonl, NO model calls;**
  every table cites its run directory + provenance (model tag/digest, seed, timestamp). Tolerates
  the older 2-source M4 schema (derives band_shift from the bands) for the dilution comparison.
- **FINAL NUMBERS (traced to run-ids):**
  - Attack (M4, 3-source) `run_20260616T132519`: 8/8 attacks succeeded; deflate mean |band shift|
    1.0 (all CRITICAL->HIGH), inflate mean 1.5 (0003/0004 +1 to HIGH; 0007/0008 +2 to CRITICAL).
  - Dilution vs 2-source `run_20260616T033459`: inflate mean |band shift| 2.0 -> 1.5 (half the
    inflation CVEs diluted from 2 bands to 1; deflate stayed 1.0). Corroboration partially resists.
  - Defense (M5, internal-consistency) `run_20260617T090409`: detection 8/8, recovery 8/8 (1.00),
    false positives 0/8 (0.00); defended band == clean band on all 8.
- **Example rationales are pulled verbatim from the jsonl** (1 deflate + 1 inflate). The real
  poisoned DEFLATION rationale shows the model PARTIALLY resisting ("the vendor re-assessed the
  risk as overstated... the initial reports of in-the-wild exploitation... remain concerning"),
  matching the 1-band partial deflation; the INFLATION one fully adopts the false urgency.
- **STUDY COMPLETE.** All numbers in RESULTS.md cross-checked against the raw jsonl. No further
  model runs.
