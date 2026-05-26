"""Regression test for ARC issue #8 — checkpoint pickle RCE.

ARC loads checkpoints via ``torch.load()``, which deserializes with
Python's ``pickle`` protocol and can execute arbitrary code through the
``__reduce__`` mechanism. This test verifies that ARC's safe-load path
(``torch.load(..., weights_only=True)``) refuses to deserialize a
malicious pickle.

The fallback path (``weights_only=False``) is intentionally permissive
for backward compatibility with checkpoints that include optimizer
state or other non-tensor objects, and is not exercised here. See
SECURITY.md for the full trust boundary.
"""

from __future__ import annotations

import pickle
from pathlib import Path

import torch


def test_malicious_pickle_blocked_by_weights_only(tmp_path: Path) -> None:
    """A pickle whose ``__reduce__`` would call ``open()`` to create a
    sentinel file must NOT execute when loaded with ``weights_only=True``.

    This mirrors the proof-of-concept in issue #8: an attacker plants a
    crafted checkpoint, ARC's autonomous rollback path picks it up,
    ``torch.load()`` runs the payload as the training user. With
    ``weights_only=True`` the unpickler refuses to call arbitrary
    callables, so the sentinel is never created.
    """
    sentinel = tmp_path / "_exploit_ran.txt"
    malicious_path = tmp_path / "malicious.pt"

    class Exploit:
        """Marker class — if its ``__reduce__`` payload runs, the
        ``open()`` builtin is called and the sentinel file appears."""

        def __reduce__(self):
            return (open, (str(sentinel), "w"))

    # Write a checkpoint-shaped pickle that hides the exploit in a key
    # ARC code paths actually read.
    with open(malicious_path, "wb") as f:
        pickle.dump({"model_state_dict": Exploit()}, f)

    # weights_only=True is expected to refuse this file. The exact
    # exception type varies across PyTorch versions; what we care about
    # is that the payload is NOT executed.
    try:
        torch.load(str(malicious_path), weights_only=True)
    except Exception:
        pass  # any refusal is fine — only the side-effect matters

    assert not sentinel.exists(), (
        f"Malicious pickle executed under weights_only=True — sentinel "
        f"{sentinel} was created by the exploit. This is a regression "
        "of issue #8; the safe-load path is broken."
    )


def test_safe_checkpoint_loads_with_weights_only(tmp_path: Path) -> None:
    """Sanity check: a tensor-only checkpoint must load cleanly under
    ``weights_only=True``. If this fails, the safe path is too strict
    and ARC's own checkpoints will hit the fallback warning."""
    safe_path = tmp_path / "safe.pt"
    expected_tensor = torch.randn(4, 4)
    torch.save({"weight": expected_tensor}, str(safe_path))

    loaded = torch.load(str(safe_path), weights_only=True)
    assert "weight" in loaded
    assert torch.equal(loaded["weight"], expected_tensor)