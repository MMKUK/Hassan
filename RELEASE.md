# Hassan releases — verified checksums (Monero-style)

## Forks on GitHub

**You cannot block forks of a public GitHub repository.** Public source is
cloneable and forkable by design. To disallow forks you must make the repo
**private** (org/personal settings). That is separate from release integrity.

What *does* protect users (like Monero): **publish binaries with checksums**
and preferably a signature over those checksums. Users verify before running.

## Build a package with SHA256SUMS

```bash
./scripts/build-dist.sh
# → dist/hassan-<os>-<arch>/
#    includes binaries + SHA256SUMS (+ optional signature)
```

## Verify before run

```bash
./scripts/verify-dist.sh dist/hassan-darwin-aarch64
# or inside the folder:
sha256sum -c SHA256SUMS    # Linux
shasum -a 256 -c SHA256SUMS  # macOS
```

## Optional: sign SHA256SUMS (pick one)

| Method | Env |
|--------|-----|
| GPG | `HASSAN_DIST_GPG_KEY=<key-id>` → `SHA256SUMS.asc` |
| SSH | `HASSAN_DIST_SSH_KEY=path` → `SHA256SUMS.sig` |
| Cosign | `COSIGN_KEY=path` → `SHA256SUMS.sig` |
| Hassan ML-DSA | `HASSAN_DIST_SIGNER_KEYSTORE=release.json` + `HASSAN_WALLET_PASSWORD` → `SHA256SUMS.abs.json` |

Example (PQ signer):

```bash
export HASSAN_WALLET_PASSWORD='…'
export HASSAN_DIST_SIGNER_KEYSTORE=./release-signer.json
./scripts/build-dist.sh
./scripts/verify-dist.sh dist/hassan-darwin-aarch64
```

Publish on GitHub Releases: the folder tarball **plus** `SHA256SUMS` (and
`.asc` / `.sig` / `.abs.json`). Post the expected release-signer address or GPG
fingerprint in the release notes so users can match the signer.

## GitHub Releases checklist

1. Tag commit: `git tag -a v0.1.0 -m "Hassan v0.1.0"`  
2. Build on each target OS (or CI) with `./scripts/build-dist.sh`  
3. Attach archives + `SHA256SUMS` (+ signature files)  
4. Users: download → verify checksums → then run  

Do **not** trust a binary that fails `SHA256SUMS` or an unexpected signer.
