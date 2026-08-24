"""Tests for the reproducibility harness (model-independent; no server needed)."""

import json
import random

import pytest

from poisoncti.utils import io, reproducibility as repro


@pytest.fixture
def cfg():
    return {
        "models": {"chat": "llama3:8b", "embed": "bge-m3", "temperature": 0.0,
                   "host": "http://localhost:11434"},
        "seed": 1337,
    }


def test_set_global_seed_is_deterministic():
    repro.set_global_seed(1337)
    a = [random.random() for _ in range(5)]
    repro.set_global_seed(1337)
    b = [random.random() for _ in range(5)]
    assert a == b


def test_decode_options_are_greedy_and_seeded(cfg):
    opts = repro.decode_options(cfg)
    assert opts == {"temperature": 0.0, "seed": 1337}


def test_build_provenance_has_required_fields(cfg, tmp_path, monkeypatch):
    lock = {
        "ollama_version": "0.1.0",
        "models": {
            "chat": {"llama3:8b": {"digest": "sha256:abc"}},
            "embed": {"bge-m3": {"digest": "sha256:def"}},
        },
    }
    lock_path = tmp_path / "models.lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    monkeypatch.setattr(repro, "MODELS_LOCK_PATH", str(lock_path))

    prov = repro.build_provenance(cfg, verify=False)
    assert prov["seed"] == 1337
    assert prov["temperature"] == 0.0
    assert prov["models"]["chat"] == {"tag": "llama3:8b", "digest": "sha256:abc"}
    assert prov["models"]["embed"] == {"tag": "bge-m3", "digest": "sha256:def"}
    assert "timestamp_utc" in prov and "poisoncti_version" in prov


def test_verify_model_pins_multi_tag(cfg, tmp_path, monkeypatch):
    """The lock is keyed by tag: several chat pins coexist; the CONFIGURED tag
    is the one verified — matching digest passes, drift or unpinned aborts."""
    lock = {
        "models": {
            "chat": {"llama3:8b": {"digest": "sha256:aaa"},
                     "mistral:7b": {"digest": "sha256:bbb"}},
            "embed": {"bge-m3": {"digest": "sha256:def"}},
        },
    }
    lock_path = tmp_path / "models.lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    def fake_resolve(c):
        return {"chat": {"tag": c["models"]["chat"], "digest": "sha256:bbb"},
                "embed": {"tag": "bge-m3", "digest": "sha256:def"}}

    monkeypatch.setattr(repro, "resolve_model_digests", fake_resolve)
    cfg["models"]["chat"] = "mistral:7b"
    repro.verify_model_pins(cfg, str(lock_path))  # pinned tag, matching digest: OK

    # drift on the configured tag aborts
    drifted = json.loads(lock_path.read_text(encoding="utf-8"))
    drifted["models"]["chat"]["mistral:7b"]["digest"] = "sha256:STALE"
    lock_path.write_text(json.dumps(drifted), encoding="utf-8")
    with pytest.raises(RuntimeError, match="digest drift"):
        repro.verify_model_pins(cfg, str(lock_path))

    # an unpinned configured tag aborts
    unpinned = json.loads(lock_path.read_text(encoding="utf-8"))
    del unpinned["models"]["chat"]["mistral:7b"]
    lock_path.write_text(json.dumps(unpinned), encoding="utf-8")
    with pytest.raises(RuntimeError, match="no pin"):
        repro.verify_model_pins(cfg, str(lock_path))


def test_digest_lookup_and_match(monkeypatch):
    # ollama list returns digests; show() does NOT — this is the bug we fixed.
    class StubClient:
        def list(self):
            return {"models": [
                {"model": "llama3:8b", "digest": "sha256:aaa"},
                {"model": "bge-m3:latest", "digest": "sha256:bbb"},
            ]}

    digests = repro.digest_lookup(StubClient())
    assert digests == {"llama3:8b": "sha256:aaa", "bge-m3:latest": "sha256:bbb"}
    # exact tag match, and bare 'bge-m3' must resolve to 'bge-m3:latest'
    assert repro.match_digest(digests, "llama3:8b") == "sha256:aaa"
    assert repro.match_digest(digests, "bge-m3") == "sha256:bbb"
    assert repro.match_digest(digests, "mistral:7b") is None


def test_jsonl_roundtrip_strips_provenance(tmp_path):
    rows = [{"item": 1}, {"item": 2}]
    prov = {"seed": 1337}
    path = tmp_path / "out.jsonl"
    io.write_jsonl(rows, str(path), provenance=prov)

    # First physical line is the provenance header...
    first = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert first == {"_provenance": prov}
    # ...and read_jsonl returns only the data rows.
    assert io.read_jsonl(str(path)) == rows


def test_write_json_embeds_provenance(tmp_path):
    path = tmp_path / "metrics.json"
    io.write_json({"asr": 0.4}, str(path), provenance={"seed": 1337})
    loaded = io.read_json(str(path))
    assert loaded["asr"] == 0.4
    assert loaded["_provenance"] == {"seed": 1337}


def test_load_config_merges_override(tmp_path):
    example = tmp_path / "settings.example.yaml"
    example.write_text("models:\n  chat: base\n  temperature: 0.0\nseed: 1\n", encoding="utf-8")
    override = tmp_path / "settings.yaml"
    override.write_text("models:\n  chat: override\nseed: 99\n", encoding="utf-8")

    cfg = io.load_config(str(override), str(example))
    assert cfg["models"]["chat"] == "override"   # overridden
    assert cfg["models"]["temperature"] == 0.0   # inherited from example
    assert cfg["seed"] == 99
