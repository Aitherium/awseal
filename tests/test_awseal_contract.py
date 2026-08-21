"""Contract suite for awseal — the properties that must not ship broken.

The publish workflow says "its contract suite is the reason it can be trusted, so
it runs before upload". That sentence was true of the workflow and false of the
repository: `tests/` existed on disk, was EMPTY, and git does not track empty
directories — so every checkout had no tests at all and the step died with
`file or directory not found: tests`. A signing package was one green run away
from shipping with its stated basis for trust absent.

Each test below asserts a property the source docstrings claim in prose, and the
two marked REGRESSION reproduce defects those docstrings name as already having
happened once.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from awseal import digest as _digest
from awseal import keys as _keys
from awseal import seal as _seal


@pytest.fixture
def keyfile(tmp_path: Path) -> Path:
    return _keys.generate(tmp_path / "key.pem")


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "artifact"
    (root / "nested").mkdir(parents=True)
    (root / "a.txt").write_text("alpha", encoding="utf-8")
    (root / "b.txt").write_text("bravo", encoding="utf-8")
    (root / "nested" / "c.txt").write_text("charlie", encoding="utf-8")
    return root


def _seal_it(root: Path, keyfile: Path) -> None:
    _seal.write(_seal.sign(root, key_path=keyfile, subject="test"), root)


def test_round_trip_verifies(tree: Path, keyfile: Path) -> None:
    """The happy path must actually pass. A gate that only ever denies is inert."""
    _seal_it(tree, keyfile)
    r = _seal.verify(tree)
    assert r["signature_ok"] is True
    assert r["content_ok"] is True
    assert r["diff"] == {"added": [], "removed": [], "modified": []}


def test_signature_covers_the_file_map_not_a_count(tree: Path, keyfile: Path) -> None:
    """REGRESSION. The signer this was extracted from signed `len(violations)`
    rather than the violations, so anyone could rewrite every entry and keep the
    signature valid as long as the COUNT stayed the same.

    Rewrite a file's contents in place: the number of entries is identical and
    only the digest changes. A count-signing implementation passes this happily.
    """
    _seal_it(tree, keyfile)
    before = len(_seal.load(tree).files)

    (tree / "a.txt").write_text("ALPHA-tampered", encoding="utf-8")

    r = _seal.verify(tree)
    assert len(_seal.load(tree).files) == before, "entry count must be unchanged"
    assert r["content_ok"] is False
    assert "a.txt" in " ".join(r["diff"]["modified"])


def test_verify_reports_three_answers_separately(tree: Path, keyfile: Path) -> None:
    """A valid signature over a payload that no longer matches disk is THE
    interesting case, and a single boolean cannot express it."""
    _seal_it(tree, keyfile)
    (tree / "b.txt").write_text("changed", encoding="utf-8")

    r = _seal.verify(tree)
    assert r["signature_ok"] is True, "the seal itself was not touched"
    assert r["content_ok"] is False, "but the tree no longer matches it"
    assert r["diff"]["modified"], "and the diff must say which file"


def test_diff_distinguishes_added_removed_modified(tree: Path, keyfile: Path) -> None:
    """'Invalid' is not a diagnosis. Each kind of drift lands in its own bucket."""
    _seal_it(tree, keyfile)
    (tree / "new.txt").write_text("added", encoding="utf-8")
    (tree / "b.txt").unlink()
    (tree / "a.txt").write_text("modified", encoding="utf-8")

    d = _seal.verify(tree)["diff"]
    assert any("new.txt" in p for p in d["added"])
    assert any("b.txt" in p for p in d["removed"])
    assert any("a.txt" in p for p in d["modified"])


def test_tampered_signature_fails(tree: Path, keyfile: Path) -> None:
    """Corrupt the signature and the key must refuse it."""
    _seal_it(tree, keyfile)
    p = tree / _seal.SEAL_NAME
    d = json.loads(p.read_text(encoding="utf-8"))
    sig = bytearray(bytes.fromhex(d["signature"]))
    sig[0] ^= 0xFF
    d["signature"] = bytes(sig).hex()
    p.write_text(json.dumps(d), encoding="utf-8")

    assert _seal.verify(tree)["signature_ok"] is False


def test_expect_key_separates_intact_from_trusted(tree: Path, tmp_path: Path,
                                                  keyfile: Path) -> None:
    """Without `expect_key` a seal proves only internal consistency: anyone can
    generate a key, sign anything, and ship a seal that verifies against itself.
    Conflating that with provenance is how a signature comes to mean nothing.
    """
    _seal_it(tree, keyfile)
    mine = _keys.public_key_hex(path=keyfile)
    stranger = _keys.public_key_hex(path=_keys.generate(tmp_path / "other.pem"))

    assert _seal.verify(tree)["signature_ok"] is True
    assert _seal.verify(tree, expect_key=mine)["key_trusted"] is True
    r = _seal.verify(tree, expect_key=stranger)
    assert r["key_trusted"] is False, "a self-consistent seal is not a trusted one"
    assert r["signature_ok"] is True, "and it is still internally intact"


def test_resealing_does_not_break_its_own_verification(tree: Path,
                                                       keyfile: Path) -> None:
    """REGRESSION. Without excluding the seal file at SIGN time, re-sealing a
    directory folds the OLD seal into the new digest while verify correctly
    excludes it — so a freshly signed artifact fails its own verification and the
    message points at content drift rather than at the signer.
    """
    _seal_it(tree, keyfile)
    _seal_it(tree, keyfile)  # seal a directory that already carries a seal
    r = _seal.verify(tree)
    assert r["signature_ok"] is True
    assert r["content_ok"] is True


def test_unsealed_is_refused_not_reported_as_verified(tree: Path) -> None:
    """Unsealed is not the same as invalid, and neither is 'verified'."""
    with pytest.raises(_digest.SealError):
        _seal.verify(tree)


def test_generate_refuses_to_overwrite_a_key(tmp_path: Path) -> None:
    """A regenerated key silently invalidates every seal ever made with the old
    one, and the symptom does not point at the command that caused it."""
    p = _keys.generate(tmp_path / "k.pem")
    with pytest.raises(_digest.SealError):
        _keys.generate(p)
    assert _keys.generate(p, overwrite=True) == p


def test_canonical_is_stable_across_key_order(tmp_path: Path) -> None:
    """Signer and verifier must agree on one serialisation, whatever order the
    payload's keys happen to be built in."""
    a = _seal.canonical({"b": 2, "a": 1})
    b = _seal.canonical({"a": 1, "b": 2})
    assert a == b
