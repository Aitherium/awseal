"""Content addressing for a directory of files.

A seal is only as good as what it covers. This module answers one question —
"what exactly am I signing?" — and answers it the same way on every machine.

THE THING THAT MAKES THIS NON-TRIVIAL

The internal attestation signer this package is extracted from signs a SUMMARY:

    payload = f"{report_id}:{window_start}:{window_end}:{total_calls}:"
              f"{cloud_calls}:{len(violations)}:{air_gap_enforced}"

Note `len(violations)` — the COUNT, not the content. Edit any violation's text
and the signature still verifies, as long as you do not change how many there
are. A signature over a summary certifies the summary, and a reader reasonably
believes it certifies the report.

So a digest here covers every byte of every file plus the relative path each
byte lives at. Paths are included because moving a file without changing its
contents changes what the artifact IS — a weight file renamed into the config
slot is a different artifact carrying the same bytes.

DETERMINISM IS THE WHOLE CONTRACT

Two machines must agree or verification is theatre. Three sources of drift are
handled explicitly:

- **Ordering.** `os.walk` order is filesystem-dependent. Entries are sorted by
  POSIX relative path.
- **Path separators.** `a\\b` on Windows and `a/b` elsewhere are the same file
  and must hash the same. Always POSIX.
- **Line endings are NOT normalised.** They are content. This is the one place
  the tempting normalisation is wrong: a script whose CRLFs were rewritten is a
  different file to the shell that runs it, and a seal that says otherwise is
  lying about the bytes that will execute.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable, Iterator

#: Read size. Large files are streamed rather than loaded — a sealed artifact is
#: routinely a multi-GB adapter, and a digest tool that needs the file in RAM is
#: unusable for exactly the artifacts that most need sealing.
_CHUNK = 1024 * 1024

#: Never sealed: caches and VCS metadata are not the artifact, they differ
#: between machines by design, and including them makes every digest unique.
DEFAULT_EXCLUDES = ("__pycache__", ".git", ".ruff_cache", ".pytest_cache",
                    ".DS_Store", ".mypy_cache")


class SealError(RuntimeError):
    """Raised rather than returning a wrong or empty answer."""


def file_digest(path: Path) -> str:
    """SHA-256 of one file's bytes, streamed."""
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            while True:
                block = fh.read(_CHUNK)
                if not block:
                    break
                h.update(block)
    except OSError as exc:
        raise SealError(f"cannot read {path}: {exc}") from exc
    return h.hexdigest()


def walk_files(root: Path, excludes: Iterable[str] = DEFAULT_EXCLUDES) -> Iterator[Path]:
    """Every sealable file under `root`, deterministically ordered."""
    ex = set(excludes)
    if not root.is_dir():
        raise SealError(f"{root} is not a directory")
    out = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if ex & set(p.relative_to(root).parts):
            continue
        out.append(p)
    # Sort on the POSIX relative path, not the native one: sorting on native
    # paths orders differently across platforms and silently produces a
    # different tree digest for identical content.
    out.sort(key=lambda p: p.relative_to(root).as_posix())
    return iter(out)


def file_map(root: Path, excludes: Iterable[str] = DEFAULT_EXCLUDES) -> Dict[str, str]:
    """`{posix relative path: sha256}` for every file under `root`."""
    files = {p.relative_to(root).as_posix(): file_digest(p)
             for p in walk_files(root, excludes)}
    if not files:
        # An empty map hashes to a perfectly stable, perfectly meaningless
        # value, and every empty directory would seal identically. That reads
        # as a successful seal of nothing.
        raise SealError(f"{root} contains no sealable files — refusing to seal "
                        f"an empty tree, which would produce a valid signature "
                        f"over nothing")
    return files


def tree_digest(files: Dict[str, str]) -> str:
    """One digest over the whole `{path: hash}` map.

    Canonical JSON with sorted keys and no insignificant whitespace, so the
    bytes hashed are a function of the content alone and not of how the dict
    was built.
    """
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def digest_tree(root: Path, excludes: Iterable[str] = DEFAULT_EXCLUDES):
    """Convenience: `(file_map, tree_digest)` for a directory."""
    files = file_map(root, excludes)
    return files, tree_digest(files)


def diff(expected: Dict[str, str], actual: Dict[str, str]) -> Dict[str, list]:
    """What changed between two file maps.

    Verification must be able to SAY what broke. "Signature invalid" sends a
    reader looking for a key problem when the real answer is usually one file
    added, removed or edited — and naming it is the difference between a
    five-minute fix and an afternoon.
    """
    exp, act = set(expected), set(actual)
    return {
        "added": sorted(act - exp),
        "removed": sorted(exp - act),
        "modified": sorted(p for p in exp & act if expected[p] != actual[p]),
    }
