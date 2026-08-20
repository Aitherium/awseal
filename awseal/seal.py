"""Sign a directory, and verify someone else's.

A seal is a small JSON document sitting beside the artifact it describes. It
carries the digest of every file, one digest over that whole map, the public key
that signed it, and the signature over a canonical serialisation.

WHAT THE SIGNATURE COVERS, AND WHY IT MATTERS THAT IT IS EVERYTHING

The signature is over the canonical JSON of the seal's `payload` — which
contains the complete `{path: sha256}` map, not a count and not a summary. The
internal signer this is extracted from signed `len(violations)` rather than the
violations; anyone could rewrite every entry and keep the signature valid so
long as the number of entries stayed the same.

VERIFY ANSWERS THREE QUESTIONS SEPARATELY

"Invalid" is not a diagnosis. A verifier that returns one boolean sends its
reader looking for a key problem when the usual answer is "you added a file".
So `verify` reports, independently:

    signature_ok   — did this key sign this payload
    content_ok     — do the files on disk match the payload
    diff           — exactly which files were added, removed or modified

All three are needed. A valid signature over a payload that no longer matches
the disk is the interesting case, and a single boolean cannot express it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from . import keys as _keys
from .digest import SealError, diff, digest_tree, file_map, tree_digest

#: Bumped only when the canonical payload shape changes. A verifier that meets
#: a version it does not know REFUSES rather than guessing: verifying a
#: document you do not fully understand is how a signature comes to certify
#: something other than what it appears to.
SEAL_VERSION = 1

#: The file a seal lives in, beside the tree it covers.
SEAL_NAME = "awseal.json"


@dataclass
class Seal:
    """A parsed seal document."""

    version: int
    tree_digest: str
    files: Dict[str, str]
    public_key: str
    signature: str
    created: str
    subject: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)

    def payload(self) -> Dict[str, Any]:
        """Exactly the bytes that were signed — no more, no less."""
        return {
            "version": self.version,
            "tree_digest": self.tree_digest,
            "files": self.files,
            "created": self.created,
            "subject": self.subject,
            "meta": self.meta,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.payload()
        d["public_key"] = self.public_key
        d["signature"] = self.signature
        return d


def canonical(payload: Dict[str, Any]) -> bytes:
    """The one serialisation both signer and verifier must agree on."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign(root: Path, *, key_path: Optional[Path] = None, subject: str = "",
         meta: Optional[Dict[str, Any]] = None) -> Seal:
    """Seal the directory `root`. Raises rather than producing a weak seal."""
    private = _keys.load_private_key(key_path)
    # Excluding the seal file here is not symmetry-for-its-own-sake: without it,
    # re-sealing a directory that already carries an `awseal.json` folds the OLD
    # seal into the new digest, while `verify` correctly excludes it — so a
    # freshly signed artifact fails its own verification, and the message points
    # at content drift rather than at the signer.
    files, digest = digest_tree(root, excludes=_excludes_with_seal())
    seal = Seal(
        version=SEAL_VERSION,
        tree_digest=digest,
        files=files,
        public_key=_keys.public_key_hex(private),
        signature="",
        created=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        subject=subject or root.name,
        meta=dict(meta or {}),
    )
    seal.signature = private.sign(canonical(seal.payload())).hex()
    return seal


def write(seal: Seal, root: Path) -> Path:
    """Write the seal beside the tree it covers."""
    target = root / SEAL_NAME
    target.write_text(json.dumps(seal.to_dict(), indent=2, sort_keys=True),
                      encoding="utf-8")
    return target


def load(root: Path) -> Seal:
    """Read a seal. Refuses anything it cannot fully understand."""
    target = root / SEAL_NAME
    if not target.is_file():
        raise SealError(f"no {SEAL_NAME} in {root} — this artifact is unsealed. "
                        f"Unsealed is not the same as invalid, and it must not "
                        f"be reported as verified")
    try:
        d = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SealError(f"cannot read {target}: {exc}") from exc
    version = d.get("version")
    if version != SEAL_VERSION:
        raise SealError(
            f"{target} is seal version {version!r}, this is version "
            f"{SEAL_VERSION}. Refusing: verifying a document whose shape you do "
            f"not know can certify something other than what it appears to")
    for req in ("tree_digest", "files", "public_key", "signature", "created"):
        if req not in d:
            raise SealError(f"{target} is missing required field {req!r}")
    if not isinstance(d["files"], dict) or not d["files"]:
        raise SealError(f"{target} covers no files — refusing")
    return Seal(version=version, tree_digest=d["tree_digest"], files=d["files"],
                public_key=d["public_key"], signature=d["signature"],
                created=d["created"], subject=d.get("subject", ""),
                meta=d.get("meta") or {})


def verify(root: Path, *, expect_key: Optional[str] = None) -> Dict[str, Any]:
    """Verify a sealed directory. Reports three answers, never one boolean.

    `expect_key` is how a consumer says "I trust THIS publisher". Without it a
    seal proves only internal consistency: anyone can generate a key, sign
    anything, and ship a seal that verifies perfectly against itself. That is
    the difference between "this artifact was not modified after sealing" and
    "this artifact came from someone I trust", and conflating them is how a
    signature comes to mean less than nothing.
    """
    seal = load(root)

    result: Dict[str, Any] = {
        "subject": seal.subject,
        "created": seal.created,
        "public_key": seal.public_key,
        "signature_ok": False,
        "content_ok": False,
        "key_trusted": None,
        "diff": {"added": [], "removed": [], "modified": []},
    }

    try:
        pub = _keys.load_public_key(seal.public_key)
        pub.verify(bytes.fromhex(seal.signature), canonical(seal.payload()))
        result["signature_ok"] = True
    except SealError:
        raise
    except Exception:  # noqa: BLE001 - any failure is a failed verification
        result["signature_ok"] = False

    # Content is checked even when the signature failed. Knowing WHICH files
    # moved is what makes a failure actionable, and suppressing it because an
    # earlier check failed is how a verifier ends up saying only "invalid".
    actual = file_map(root, excludes=_excludes_with_seal())
    result["content_ok"] = (tree_digest(actual) == seal.tree_digest)
    result["diff"] = diff(seal.files, actual)

    if expect_key is not None:
        result["key_trusted"] = (seal.public_key == expect_key.strip().lower())

    result["ok"] = bool(result["signature_ok"] and result["content_ok"]
                        and (result["key_trusted"] is not False))
    return result


def _excludes_with_seal():
    """The seal file itself is never part of what it covers.

    Obvious once stated and easy to get wrong: including `awseal.json` in its
    own digest is unsatisfiable, because writing the signature changes the file
    being hashed.
    """
    from .digest import DEFAULT_EXCLUDES
    return tuple(DEFAULT_EXCLUDES) + (SEAL_NAME,)
