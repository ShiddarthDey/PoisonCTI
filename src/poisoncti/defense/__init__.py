"""Defense: a lightweight, no-retraining cross-source consistency check.

The defender controls only the agent side. Instead of trusting the top-ranked
chunk, the defense looks across the retrieved sources and flags when a lone source
disagrees with the broader evidence — the signature of a single injected poison.
It runs at retrieval time, costs no training, and either down-weights/excludes the
outlier or abstains, then the pipeline re-derives the judgement.

Submodule:
    consistency -- score cross-source agreement, detect outliers, return a defense report
"""
