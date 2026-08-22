"""`awseal` — the command line.

    awseal keygen                       create a signing key
    awseal pubkey                       print the public half (safe to publish)
    awseal sign  <dir> [--subject NAME] write awseal.json into <dir>
    awseal verify <dir> [--key HEX]     check it, and say what moved
    awseal --self-test                  prove the rules still hold

`verify` exits 1 on a failed verification and 2 when it could not judge at all
— a missing seal, an unreadable directory, an unknown seal version. Those are
different answers and collapsing them is how "I could not check" becomes
"it checked out".
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import keys as _keys
from . import seal as _seal
from .digest import SealError


def _cmd_keygen(a) -> int:
    path = _keys.generate(Path(a.path) if a.path else None, overwrite=a.force)
    print(f"wrote {path}")
    print(f"public key: {_keys.public_key_hex(path=path)}")
    print("Publish the PUBLIC key. Anyone holding it can verify your artifacts "
          "and nobody can sign with it.")
    return 0


def _cmd_pubkey(a) -> int:
    print(_keys.public_key_hex(path=Path(a.path) if a.path else None))
    return 0


def _cmd_sign(a) -> int:
    root = Path(a.directory)
    s = _seal.sign(root, key_path=Path(a.key_path) if a.key_path else None,
                   subject=a.subject or "")
    target = _seal.write(s, root)
    print(f"sealed {len(s.files)} file(s) -> {target}")
    print(f"tree digest: {s.tree_digest}")
    print(f"public key:  {s.public_key}")
    return 0


def _cmd_verify(a) -> int:
    root = Path(a.directory)
    r = _seal.verify(root, expect_key=a.key)
    if a.json:
        print(json.dumps(r, indent=2, sort_keys=True))
    else:
        print(f"subject:      {r['subject']}")
        print(f"created:      {r['created']}")
        print(f"signature_ok: {r['signature_ok']}")
        print(f"content_ok:   {r['content_ok']}")
        if r["key_trusted"] is None:
            # Say this out loud. A seal with no expected key proves only that
            # the artifact was not modified after SOMEONE sealed it — and
            # anyone can generate a key. Reporting that as a clean pass is the
            # difference between "unmodified" and "trustworthy".
            print("key_trusted:  UNCHECKED — no --key given, so this proves the "
                  "artifact is unmodified since sealing, NOT who sealed it")
        else:
            print(f"key_trusted:  {r['key_trusted']}")
        for kind in ("added", "removed", "modified"):
            for p in r["diff"][kind]:
                print(f"  {kind:8} {p}")
    return 0 if r["ok"] else 1


def self_test() -> int:
    """Round-trip the real primitives; prove each refusal still refuses."""
    import tempfile
    ok = True

    def chk(label, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'PASS' if good else 'FAIL'}  {label} -> {got!r} (want {want!r})")

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        keyfile = d / "k.key"
        _keys.generate(keyfile)

        art = d / "artifact"
        art.mkdir()
        (art / "a.txt").write_text("hello", encoding="utf-8")
        (art / "sub").mkdir()
        (art / "sub" / "b.bin").write_bytes(b"\x00\x01\x02")

        s = _seal.sign(art, key_path=keyfile, subject="demo")
        _seal.write(s, art)
        r = _seal.verify(art)
        chk("a freshly sealed tree verifies", r["ok"], True)
        chk("  signature holds", r["signature_ok"], True)
        chk("  content holds", r["content_ok"], True)

        # Re-sealing must not be poisoned by the previous seal file.
        s2 = _seal.sign(art, key_path=keyfile, subject="demo")
        _seal.write(s2, art)
        chk("re-sealing an already-sealed tree still verifies",
            _seal.verify(art)["ok"], True)

        # TAMPER: content changes, signature is untouched. This is the case a
        # single boolean cannot express, and the reason verify reports three.
        (art / "a.txt").write_text("goodbye", encoding="utf-8")
        r = _seal.verify(art)
        chk("tampered content fails", r["ok"], False)
        chk("  but the signature is still valid (the interesting case)",
            r["signature_ok"], True)
        chk("  and the diff NAMES the file", r["diff"]["modified"], ["a.txt"])
        (art / "a.txt").write_text("hello", encoding="utf-8")

        # ADDING a file must break the seal too. A digest over only the files
        # it knows about would happily ignore a smuggled extra.
        (art / "extra.sh").write_text("rm -rf /", encoding="utf-8")
        r = _seal.verify(art)
        chk("an ADDED file breaks the seal", r["content_ok"], False)
        chk("  and is named", r["diff"]["added"], ["extra.sh"])
        (art / "extra.sh").unlink()
        chk("removing it restores the seal", _seal.verify(art)["ok"], True)

        # A DIFFERENT key must not verify — the whole point of asymmetry.
        other = d / "other.key"
        _keys.generate(other)
        r = _seal.verify(art, expect_key=_keys.public_key_hex(path=other))
        chk("a foreign public key is not trusted", r["key_trusted"], False)
        chk("  and that alone fails the verification", r["ok"], False)
        r = _seal.verify(art, expect_key=_keys.public_key_hex(path=keyfile))
        chk("the real publisher key is trusted", r["key_trusted"], True)

        # FORGERY: re-sign with another key and keep the content. Content is
        # intact and the signature is internally valid — only expect_key
        # separates this from the genuine article.
        forged = _seal.sign(art, key_path=other, subject="demo")
        _seal.write(forged, art)
        r = _seal.verify(art)
        chk("a forged seal is internally consistent (why expect_key exists)",
            r["signature_ok"] and r["content_ok"], True)
        r = _seal.verify(art, expect_key=_keys.public_key_hex(path=keyfile))
        chk("  but is rejected against the expected publisher", r["ok"], False)

        # REFUSALS. Every one of these must raise rather than return a verdict.
        for label, fn in (
            ("unsealed directory", lambda: _seal.verify(d / "artifact2")),
            ("empty tree", lambda: _seal.sign(_mkempty(d), key_path=keyfile)),
            ("missing key", lambda: _seal.sign(art, key_path=d / "nope.key")),
        ):
            try:
                fn()
                chk(f"refuses: {label}", "no raise", "raise")
            except SealError:
                chk(f"refuses: {label}", "raise", "raise")

        # An unknown seal VERSION must refuse, not guess.
        bad = json.loads((art / _seal.SEAL_NAME).read_text(encoding="utf-8"))
        bad["version"] = 999
        (art / _seal.SEAL_NAME).write_text(json.dumps(bad), encoding="utf-8")
        try:
            _seal.load(art)
            chk("refuses: unknown seal version", "no raise", "raise")
        except SealError:
            chk("refuses: unknown seal version", "raise", "raise")

        # A malformed public key must refuse rather than verify-as-false: a
        # caller cannot tell "wrong key" from "not a key" otherwise.
        for label, hexkey in (("not hex", "zzzz"), ("wrong length", "ab" * 8)):
            try:
                _keys.load_public_key(hexkey)
                chk(f"refuses: public key {label}", "no raise", "raise")
            except SealError:
                chk(f"refuses: public key {label}", "raise", "raise")

        # Overwriting a key silently invalidates every existing seal.
        try:
            _keys.generate(keyfile)
            chk("refuses: overwriting an existing key", "no raise", "raise")
        except SealError:
            chk("refuses: overwriting an existing key", "raise", "raise")

    print("\nself-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def _mkempty(base: Path) -> Path:
    e = base / "empty"
    e.mkdir(exist_ok=True)
    return e


def main(argv=None) -> int:
    # GENERATED doctor intercept (gen_aw_doctor.py) -- do not edit
    _dv = locals().get("argv")
    if (_dv if _dv is not None else __import__("sys").argv[1:])[:1] == ["doctor"]:
        from ._doctor import report
        return report()
    ap = argparse.ArgumentParser(prog="awseal", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    g = sub.add_parser("keygen", help="create a signing key")
    g.add_argument("--path")
    g.add_argument("--force", action="store_true",
                   help="overwrite an existing key (invalidates every seal "
                        "made with it)")
    g.set_defaults(fn=_cmd_keygen)

    p = sub.add_parser("pubkey", help="print the public key")
    p.add_argument("--path")
    p.set_defaults(fn=_cmd_pubkey)

    s = sub.add_parser("sign", help="seal a directory")
    s.add_argument("directory")
    s.add_argument("--subject")
    s.add_argument("--key-path")
    s.set_defaults(fn=_cmd_sign)

    v = sub.add_parser("verify", help="verify a sealed directory")
    v.add_argument("directory")
    v.add_argument("--key", help="the publisher's public key you expect")
    v.add_argument("--json", action="store_true")
    v.set_defaults(fn=_cmd_verify)

    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not getattr(a, "fn", None):
        ap.print_help()
        return 2
    try:
        return a.fn(a)
    except SealError as exc:
        # Exit 2, not 1: "I could not check this" is a different answer from
        # "this failed the check", and a caller that conflates them will read
        # an unreadable artifact as a clean one.
        print(f"COULD NOT VERIFY: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
