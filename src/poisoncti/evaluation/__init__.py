"""Evaluation: did poisoning work, and did the defense restore reliability?

Scoping (see DECISIONS.md, M3): SEVERITY is the PRIMARY steering axis (exact vs NVD
gold); ATT&CK mapping is SECONDARY/best-effort because a small local model cannot
reliably map fine-grained techniques.

PRIMARY (severity, exact NVD gold):
    - severity_drift: |agent - gold| and its change clean->poisoned
    - severity_asr:   fraction of targeted items deflated past a margin (critical->low)
SECONDARY (ATT&CK mapping, CAVEATED):
    - mapping_change_rate: does poison PERTURB the mapped technique set at all
      (NOT accuracy vs a gold technique — the clean mapping is itself unreliable)

Defense is judged on severity, BOTH sides of the ledger:
    - recovery rate on POISONED items (how much severity steering it undoes), and
    - false-positive rate on CLEAN multi-source items (how often it wrongly flags an
      honest source). The corpus is built with natural source-to-source disagreement
      so this FP challenge is real, not trivial.

Submodules:
    gold       -- load severity gold (NVD CVSS); technique gold is dropped (see M3)
    metrics    -- severity drift/ASR, defense recovery/FP-rate, mapping-change rate
    experiment -- run the clean/poison/defense conditions and log raw results
"""
