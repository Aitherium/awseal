# awseal

Sign an artifact so a stranger can verify it.

`awseal` puts an Ed25519 signature over every byte of a directory and writes a
small `awseal.json` beside it. The key that verifies is not the key that signs,
so you can publish the public half and anyone can check your work.

```bash
pip install awseal

awseal keygen                                   # once
awseal sign ./my-adapter --subject my-adapter   # writes awseal.json
awseal pubkey                                   # publish this

# someone else, later:
awseal verify ./my-adapter --key <your-public-key>
```

```python
import awseal
from pathlib import Path

seal = awseal.sign(Path("my-adapter"))
awseal.write(seal, Path("my-adapter"))

r = awseal.verify(Path("my-adapter"), expect_key=PUBLISHER_KEY)
r["ok"]             # everything held
r["signature_ok"]   # this key signed this payload
r["content_ok"]     # the files still match
r["diff"]           # exactly which files were added/removed/modified
```

## Three rules, each learned by breaking it

**1. There is no default key.** `awseal` raises when it cannot find one. The
signer this was extracted from read its secret from an environment variable
with a literal fallback baked into the source — and that variable was set
nowhere, so every signature it produced was forgeable by anyone who opened the
file, and its verifier returned `True` for the forgery. A verifier that
certifies forgeries is worse than no verifier: it converts *unverified* into
*verified*.

**2. The signature covers the content, not a summary.** The original signed a
payload containing `len(violations)` — the count of the findings, not the
findings. Rewrite every entry and the signature still checks out, provided you
keep the same number of them. Here the signed payload contains the full
`{path: sha256}` map, and paths are included because a file moved into another
slot is a different artifact carrying the same bytes.

**3. `ok` is not one question.** `verify` reports `signature_ok`, `content_ok`
and a `diff` separately, because the interesting failure is a *valid signature
over a payload that no longer matches the disk* — and one boolean cannot say
that. "Invalid" sends a reader hunting for a key problem when the answer is
usually "you added a file", which the diff names outright.

## What a seal does and does not prove

Without `--key`, a seal proves the artifact has not changed since **someone**
sealed it. Anyone can generate a key and sign anything, so that is a statement
about tampering, not about origin. Passing the publisher's public key is what
turns it into *this came from them*. The CLI says so on every run rather than
letting a bare pass be misread.

Line endings are **not** normalised. They are content: a script whose CRLFs
were rewritten is a different file to the shell that runs it, and a seal saying
otherwise would be lying about the bytes that execute.

## Licence

Apache-2.0.

---

## The aw family

Standalone tools that share one idea: **replace something you would otherwise have to _trust_ with something you can _check_.**

Each installs on its own, works offline, and needs no account.

| | instead of trusting | you check |
|---|---|---|
| [awnix](https://github.com/Aitherium/awnix) | that the box is what you left it as | an immutable image you built, with atomic rollback |
| [awnode](https://github.com/Aitherium/awnode) | a vendor's cloud with every prompt | a local gateway routing to backends you chose |
| [awgit](https://github.com/Aitherium/awgit) | that no one else is editing this file | a lease, refused at commit time if you do not hold it |
| [awgraph](https://github.com/Aitherium/awgraph) | that grep found everything | an AST + tree-sitter call graph an agent can traverse |
| **awseal** _(you are here)_ | that the artifact came from who you think | an Ed25519 seal — the key that verifies is not the key that forges |
| [awshare](https://github.com/Aitherium/awshare) | that the download is intact | content-addressed bundles, verified on fetch |
| [awrelay](https://github.com/Aitherium/awrelay) | a SaaS in the middle of your agents | findings, alerts and coordination over your own transport |
| [awm](https://github.com/Aitherium/awm) | that memory stayed in its lane | tenant:user:project scopes, so a write cannot cross a boundary |
| [awrecover](https://github.com/Aitherium/awrecover) | that the restore worked | a restore that fully lands or does not land at all |

[**awnix**](https://github.com/Aitherium/awnix) is the ground floor — a bootable, immutable Linux base for machines where software writes software.
