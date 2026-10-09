"""sign_files / verify_files / from_dict: a seal over a {path: sha256} map.

The map form is what seals a snapshot whose bytes live in an object store. Its
signature check is the only thing that says WHO sealed it, so each test below
tampers with the seal document itself, not only with the files under it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from awseal import keys as _keys
from awseal import seal as _seal
from awseal.digest import SealError, tree_digest


def _h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


FILES = {"a.txt": _h(b"alpha"), "d/b.txt": _h(b"bravo")}


@pytest.fixture
def keyfile(tmp_path: Path) -> Path:
    return _keys.generate(tmp_path / "owner.pem")


@pytest.fixture
def owner(keyfile: Path) -> str:
    return _keys.public_key_hex(path=keyfile)


def _roundtrip(seal: _seal.Seal) -> _seal.Seal:
    return _seal.from_dict(json.loads(json.dumps(seal.to_dict())))


def test_a_map_seal_verifies_against_its_map_and_its_owner(keyfile, owner):
    s = _roundtrip(_seal.sign_files(FILES, key_path=keyfile, meta={"modes": {"a.txt": 420}}))
    r = _seal.verify_files(s, dict(FILES), expect_key=owner)
    assert r["ok"] is True and r["signature_ok"] is True
    assert r["content_ok"] is True and r["key_trusted"] is True


def test_a_rewritten_seal_keeping_the_owner_signature_is_refused(keyfile, owner):
    """The store writer swaps the manifest AND edits the seal's files map and
    tree_digest to match it, keeping the owner's public key and old signature.
    Content and key both look right; only the signature check stands between."""
    s = _roundtrip(_seal.sign_files(FILES, key_path=keyfile))
    swapped = dict(FILES, **{"a.txt": _h(b"attacker")})
    d = s.to_dict()
    d["files"] = swapped
    d["tree_digest"] = tree_digest(swapped)
    forged = _seal.from_dict(d)
    r = _seal.verify_files(forged, swapped, expect_key=owner)
    assert r["content_ok"] is True and r["key_trusted"] is True
    assert r["signature_ok"] is False and r["ok"] is False


def test_signed_meta_cannot_be_edited(keyfile, owner):
    s = _seal.sign_files(FILES, key_path=keyfile, meta={"modes": {"a.txt": 420}})
    d = s.to_dict()
    d["meta"] = {"modes": {"a.txt": 0o4777}}
    r = _seal.verify_files(_seal.from_dict(d), dict(FILES), expect_key=owner)
    assert r["signature_ok"] is False and r["ok"] is False


def test_a_garbage_signature_is_a_failed_verification_not_a_crash(keyfile):
    d = _seal.sign_files(FILES, key_path=keyfile).to_dict()
    d["signature"] = "zz"
    r = _seal.verify_files(_seal.from_dict(d), dict(FILES))
    assert r["signature_ok"] is False and r["ok"] is False


def test_a_seal_whose_map_disagrees_with_its_own_digest_is_not_content_ok(keyfile):
    d = _seal.sign_files(FILES, key_path=keyfile).to_dict()
    d["files"] = dict(FILES, extra=_h(b"x"))
    r = _seal.verify_files(_seal.from_dict(d), dict(FILES))
    assert r["content_ok"] is False and r["ok"] is False


def test_a_different_map_reports_its_diff(keyfile, owner):
    s = _seal.sign_files(FILES, key_path=keyfile)
    actual = {"a.txt": _h(b"changed"), "new.txt": _h(b"n")}
    r = _seal.verify_files(s, actual, expect_key=owner)
    assert r["content_ok"] is False and r["ok"] is False
    assert r["diff"]["modified"] == ["a.txt"]
    assert r["diff"]["added"] == ["new.txt"] and r["diff"]["removed"] == ["d/b.txt"]


def test_another_key_is_not_trusted(keyfile, tmp_path):
    s = _seal.sign_files(FILES, key_path=keyfile)
    other = _keys.public_key_hex(path=_keys.generate(tmp_path / "other.pem"))
    r = _seal.verify_files(s, dict(FILES), expect_key=other)
    assert r["signature_ok"] is True and r["key_trusted"] is False and r["ok"] is False


@pytest.mark.parametrize("files", [{}, {"a": "not-a-digest"}, {"a": "A" * 64}])
def test_sign_files_refuses_an_empty_or_non_sha256_map(keyfile, files):
    with pytest.raises(SealError):
        _seal.sign_files(files, key_path=keyfile)


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(version=99),
    lambda d: d.pop("signature"),
    lambda d: d.pop("tree_digest"),
    lambda d: d.update(files={}),
    lambda d: d.update(files=["a"]),
])
def test_from_dict_refuses_what_it_cannot_fully_read(keyfile, mutate):
    d = _seal.sign_files(FILES, key_path=keyfile).to_dict()
    mutate(d)
    with pytest.raises(SealError):
        _seal.from_dict(d)


def test_from_dict_refuses_a_non_document():
    with pytest.raises(SealError):
        _seal.from_dict(["not", "a", "seal"])  # type: ignore[arg-type]
