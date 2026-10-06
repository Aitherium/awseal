# awseal for agents

Read this if you are an agent (or a human) editing this package. Short on
purpose: the commands, the traps that cost a session, and where the rest lives.
Nothing here is read at runtime — it is for you.

## What this is

PyPI distribution **`awseal`** (version in `pyproject.toml`), import package
`awseal`, Python >= 3.10. Sign an artifact so a stranger can verify it.
"Download this and run it" is a request for trust with nothing behind it.

This repository is a **synced mirror** of the AitherOS monorepo (lane
`.github/workflows/sync-awseal.yml`). Hand edits made here are overwritten on
the next sync — change the source and let the lane publish.

## Build, test, verify

```bash
python -m pytest tests -q        # the suite: 10 tests, green at v0.1.1
pip install -e .                 # editable install for developing against it
```

The suite was run from a source checkout with no prior install. The publish
lane (`publish-brick.yml`) additionally builds the wheel, installs it and
imports it — a tree that tests green can still ship a broken wheel.

## Rules that keep this useful

- **The contract test is the product.** `test_awseal_contract.py` pins the
  signature envelope and the verify path together; a change to the signed
  shape and its verification land in the same commit, or every artifact
  sealed before the change becomes unverifiable with no error that says so.
- **A verifier you must sign to run is not a verifier.** Keep the verify path
  key-free where the format allows it; anything that weakens that boundary is
  a design change, not a bugfix.
- **Fail loudly on a bad signature.** A verifier that returns False quietly
  gets read as "not sealed" — different fact, different response. Keep the
  distinction in the return value, like the sibling integrations do.
- **The registry drives the public surface.** This repo's README header,
  `llms.txt` and `aither-manifest.json` are generated from the ecosystem
  registry (one yaml in the AitherOS monorepo) and rewritten on every sync.
  Change the registry; do not hand-edit the generated blocks.

## Read next

- `llms.txt` — the install/use card written for an agent to execute
- `README.md` — the human front door
- `docs/` — the generated docs site source
