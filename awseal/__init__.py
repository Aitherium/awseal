"""awseal — sign an artifact so a stranger can verify it.

Extracted from AitherOS's attestation plane. The internal version signs
compliance reports with HMAC over a shared secret; this one signs a directory
with Ed25519, so the key that verifies is not the key that forges.

    import awseal

    awseal.keygen()                       # once
    seal = awseal.sign(Path("my-adapter"))
    awseal.write(seal, Path("my-adapter"))

    result = awseal.verify(Path("my-adapter"), expect_key=PUBLISHER_KEY)
    result["ok"]            # everything held
    result["signature_ok"]  # this key signed this payload
    result["content_ok"]    # the files still match
    result["diff"]          # exactly what moved

Three rules the internal version taught by breaking them:

1. **No default key.** A signer that falls back to a constant produces
   signatures anyone can forge, and its verifier then certifies the forgery.
2. **Sign the content, not a summary.** A signature over `len(items)` stays
   valid while every item is rewritten.
3. **`ok` is not one question.** A valid signature over a payload that no
   longer matches the disk is the interesting case, and one boolean cannot say
   it.
"""

from __future__ import annotations

from .digest import SealError, diff, digest_tree, file_digest, tree_digest
from .keys import generate as keygen
from .keys import load_private_key, load_public_key, public_key_hex
from .seal import SEAL_NAME, SEAL_VERSION, Seal, load, sign, verify, write

__version__ = "0.1.0"

__all__ = [
    "SEAL_NAME",
    "SEAL_VERSION",
    "Seal",
    "SealError",
    "diff",
    "digest_tree",
    "file_digest",
    "keygen",
    "load",
    "load_private_key",
    "load_public_key",
    "public_key_hex",
    "sign",
    "tree_digest",
    "verify",
    "write",
]
