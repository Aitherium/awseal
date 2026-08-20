"""Ed25519 keys, and the reason this is not HMAC.

WHY ASYMMETRIC, MEASURED RATHER THAN PREFERRED

The internal signer this package is extracted from uses HMAC-SHA256 over a
shared secret read from `AITHER_AUDIT_SIGNING_KEY`, defaulting to a literal
string in the source when that variable is unset. Measured 2026-08-19: that
variable is set in no compose file, no unit, no env file and no config in this
repo. Every report signed by that path is therefore signed with a constant a
reader can find by opening the file, and its verifier returns True for anything
signed with it. A verifier that certifies forgeries is worse than no verifier,
because it converts "unverified" into "verified".

Even set correctly, HMAC is the wrong shape for the job this package exists to
do. Verification requires the SAME secret used to sign, so a stranger can only
check an artifact if we hand them the key that also lets them forge one. There
is no way to publish a community artifact anyone can verify.

Ed25519 splits those: the private key signs, the public key verifies, and
publishing the public key gives away nothing.

FAIL CLOSED, LOUDLY

No default key, no fallback, no "unsigned but returns True". A missing key is an
error at the moment of use. That is the single most important difference from
the code this replaces, and it is the reason `load_private_key` has no
`default=` parameter to be tempted by.
"""

from __future__ import annotations

import os
import warnings
from pathlib import Path
from typing import Optional

from .digest import SealError

try:  # pragma: no cover - exercised by the import-failure path in tests
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

#: Where a private key lives when not given explicitly. A file, not an env var:
#: an env var holding a private key leaks into `ps`, into child processes, and
#: into every subprocess log that dumps its environment.
DEFAULT_KEY_PATH = Path.home() / ".aither" / "awseal" / "signing.key"

#: Env var naming an ALTERNATIVE key FILE. Deliberately a path, never the key
#: material itself, for the reason above.
KEY_PATH_ENV = "AWSEAL_KEY_PATH"


def _require_crypto() -> None:
    if not _HAVE_CRYPTO:
        raise SealError(
            "the `cryptography` package is required to sign or verify. It is a "
            "hard dependency rather than an optional one on purpose: a seal "
            "library that degrades to 'signing unavailable, continuing' is the "
            "failure this package exists to prevent")


def generate(path: Optional[Path] = None, *, overwrite: bool = False) -> Path:
    """Create a new Ed25519 private key. Returns the path written.

    Refuses to overwrite by default. A regenerated key silently invalidates
    every seal ever made with the old one, and the symptom — "all my artifacts
    stopped verifying" — does not point at the command that caused it.
    """
    _require_crypto()
    target = Path(path or _default_path())
    if target.exists() and not overwrite:
        raise SealError(
            f"{target} already exists. Overwriting it invalidates every seal "
            f"made with the current key, and nothing downstream can tell that "
            f"from tampering. Pass overwrite=True only if you mean it")
    target.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    target.write_bytes(pem)
    try:
        os.chmod(target, 0o600)
    except OSError as exc:
        # Windows does not honour POSIX modes, so this is not fatal — but it is
        # not nothing either: the private key may be readable by every account
        # on the machine. The first draft of this handler was `pass` with a
        # comment saying the caller deserves to know, which is the whole
        # swallowed-exception failure in miniature: a comment is not a warning.
        warnings.warn(
            f"could not restrict permissions on {target} ({exc}). The private "
            f"key may be readable by other users on this machine.",
            RuntimeWarning, stacklevel=2)
    return target


def _default_path() -> Path:
    env = os.environ.get(KEY_PATH_ENV)
    return Path(env) if env else DEFAULT_KEY_PATH


def load_private_key(path: Optional[Path] = None):
    """Load the signing key. Raises if absent — there is deliberately no default.

    The code this replaces had `os.environ.get(VAR, "a-literal-default")`. That
    one line is why unsigned data looked signed for the life of the system.
    """
    _require_crypto()
    target = Path(path or _default_path())
    if not target.is_file():
        raise SealError(
            f"no signing key at {target}. Create one with `awseal keygen`. "
            f"There is no default key: signing with a constant makes every "
            f"signature forgeable by anyone who can read the source")
    try:
        return serialization.load_pem_private_key(target.read_bytes(),
                                                  password=None)
    except Exception as exc:  # noqa: BLE001 - any failure here is unusable
        raise SealError(f"cannot load private key {target}: {exc}") from exc


def public_key_hex(private_key=None, path: Optional[Path] = None) -> str:
    """The public half, hex-encoded — safe to publish, and meant to be."""
    _require_crypto()
    key = private_key or load_private_key(path)
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def load_public_key(hex_key: str):
    """A verifier's view: a public key from its hex form."""
    _require_crypto()
    if not isinstance(hex_key, str) or not hex_key.strip():
        raise SealError("public key must be a non-empty hex string")
    try:
        raw = bytes.fromhex(hex_key.strip())
    except ValueError as exc:
        raise SealError(f"public key is not valid hex: {exc}") from exc
    if len(raw) != 32:
        raise SealError(
            f"an Ed25519 public key is 32 bytes; got {len(raw)}. Refusing "
            f"rather than attempting a verification that cannot succeed")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:  # noqa: BLE001
        raise SealError(f"not a valid Ed25519 public key: {exc}") from exc
