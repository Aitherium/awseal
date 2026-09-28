# Image-digest seal: an SBOM bound to an awnix/garg image digest

This is the seal format the awnix and garg CI lanes produce for every pushed image
digest. It is item G9 of the AFRL proof plan, and it is the Step 0 witness. Two
pieces make it:

- the producer, `.DEPLOYMENT/standalone/bootc/sbom-seal-awnix-image.sh`
- the lane, `.github/workflows/awnix-sbom-seal.yml`

## The seal directory

Each image digest gets one directory, for example `sbom-seal/awnix-216b78988500/`:

| file | contents |
|---|---|
| `digest.txt` | `key=value` lines: `ref=<repo>@sha256:<d>`, `repo=`, `digest=`, `syft=<pinned version>`, `spdx_packages=<n>`, `cosign_attest=ok\|skipped-no-cosign\|skipped-by-flag`, `created=<UTC>` |
| `sbom.spdx.json` | the SPDX-JSON that syft (pinned by version and tarball sha256) produced by scanning `registry:<repo>@sha256:<d>`. The scan targets the digest, never a tag. |
| `awseal.json` | an Ed25519 awseal seal (version 1) over the two files above, with subject `awnix-image:sha256:<d>` |

The seal covers the full `{path: sha256}` map. Changing one byte of the SBOM, or
changing the digest line, makes verification fail. If you move a seal from one image
to another, `--ref` catches it.

The same SBOM can also be attached to the image in the registry with
`cosign attest --type spdxjson`, signed keyless through GitHub OIDC. Keyless signing
writes an entry to the PUBLIC Sigstore Rekor transparency log (the Fulcio cert names
the Aitherium/AitherOS workflow and the image digest), which is an external
publication. It is therefore OFF by default: the owner opts in with the repository
variable `AWNIX_ATTEST_PUBLIC_REKOR=true` (automatic runs) or the `attest` input
(manual runs). With the opt-in on, the lane passes `--require-attest`, so a missing
cosign fails the run rather than going green without the attestation. `digest.txt`
records what happened (`ok`, `skipped-by-flag`, or `skipped-no-cosign` when the
producer is run by hand without the flag).

## Where the digests come from

On `workflow_run` after "Build awnix ISO", the lane reads every file in that run's
`awnix-digests` artifact and normalises it with
`sbom-seal-awnix-image.sh normalize-digests`. Both producer forms are accepted:
`repo@sha256:<64hex>`, and `<repo[:tag]> sha256:<64hex>` (what
`publish-awnix-images.sh --digests-out` writes, one line per tag pushed). Tags are
stripped to the repository and duplicates are dropped. A line that is only a tag
exits 1. If a push, schedule or dispatch build uploaded no artifact, the run FAILS,
because that build pushed digests that are now unsealed. Only a pull_request build,
which pushes nothing, is skipped with a notice.

The lane authenticates with the job-scoped `GITHUB_TOKEN` (`packages: write`) and
never with an org-admin PAT.

## Keys

- The signing key is stored in the repository secret `AWSEAL_SIGNING_KEY` (a PEM). The
  lane writes it to a 0600 temp file (`AWSEAL_KEY_PATH`) and removes that file on
  exit. The key is never echoed.
- The public key (64 hex characters) is committed at
  `.DEPLOYMENT/standalone/bootc/awseal-image.pub`. As of 2026-09-28 neither the
  secret nor this file exists yet: the owner mints the key (`awseal keygen`), sets the
  secret, and commits the public half. Until then the lane fails loudly with exit 2
  and never produces an unsealed SBOM. The lane also requires the committed
  public key (`AWSEAL_REQUIRE_PUBKEY=1`): if that file is absent it exits 2 rather
  than accepting whichever key is present. The producer refuses to sign with any key
  whose public half does not match that file, which stops a stray key from minting a
  seal that looks official.

## Offline verification (no network, no GitHub)

```sh
pip install AitherOS/packages/awseal          # or the vendored wheel
awseal verify sbom-seal/awnix-216b78988500 \
  --key "$(cat .DEPLOYMENT/standalone/bootc/awseal-image.pub)"; echo "rc=$?"
# rc=0: signature_ok, content_ok and key_trusted are all true

sh .DEPLOYMENT/standalone/bootc/sbom-seal-awnix-image.sh \
  --verify sbom-seal/awnix-216b78988500 \
  --key "$(cat .DEPLOYMENT/standalone/bootc/awseal-image.pub)" \
  --ref ghcr.io/aitherium/awnix@sha256:<d>; echo "rc=$?"
# additionally checks the seal is for THIS digest
```

Exit codes are 0 verified, 1 failed (bad signature, changed content, foreign key or
wrong ref), and 2 could not judge (missing files or awseal not installed).

Negative control: append one byte to `sbom.spdx.json` and verify again. The result
is `rc=1`, and the diff reports `modified sbom.spdx.json`. The script's
`--self-test` asserts exactly this case.

Registry-side check, which needs network access:

```sh
cosign verify-attestation --type spdxjson \
  --certificate-identity-regexp 'https://github.com/Aitherium/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/aitherium/awnix@sha256:<d>; echo "rc=$?"
```

## What makes it MEASURED

The proof plan labels G9 MEASURED only after a hosted run on a real awnix or garg
digest leaves all three records, and each one is re-run with its exit code:

1. `test -s <dir>/sbom.spdx.json` gives 0
2. `awseal verify <dir> --key <pub>` gives 0
3. `cosign verify-attestation --type spdxjson ...` gives 0 (only if the owner opted
   into the public-Rekor attestation; otherwise the awseal seal is the sole witness
   and the proof plan must say so)

The same run must also show the tampered-SBOM negative control giving 1. The
supply-chain pins are asserted by
`python AitherOS/dev/tools/check_awnix_supply_chain.py`:

- SSC001: base FROMs are pinned by digest against `base-images.lock`
- SSC002: Actions are pinned by SHA
- SSC003: every image-pushing lane either calls the producer or has an
  `actions/upload-artifact` step named `awnix-digests` and is listed in the lane's
  `workflow_run` (a mention in a comment does not count; a planned lane that does
  not exist yet is printed as ABSENT)

## Related

- `AitherOS/dev/tools/pin_awnix_base.py`: `--check` runs offline and `--refresh`
  resolves registry digests into `base-images.lock`.
- `.DEPLOYMENT/standalone/bootc/gen-image-notices.sh`: writes
  `/usr/share/licenses/awnix/THIRD-PARTY-INVENTORY.tsv` (every RPM and Python
  distribution in the image) and a customer-facing `THIRD-PARTY-NOTICES.md` (only the
  Redistributed components with their upstream, licence and modification status; no
  internal build paths or intake notes) into the image. The inventory, not the
  notices list, is authoritative for what a given image contains.
