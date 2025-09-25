# sigmate

A modern CLI for cryptographic file signing and verification.

* Ed25519 signatures
* Raw .sig files and central JSON metadata
* CycloneDX SBOM generation
* MD5/SHA1/SHA256/SHA512 checksum support
* Explicit trust store and keyring
* CI-friendly JSON output
* Idempotent signing with safe overwrite via --force


## Table of contents

* [Install](#install)
* [Quick start](#quick-start)
* [Concepts](#concepts)
* [Usage](#usage)

  * [sign](#sign)
  * [verify (signatures)](#verify-signatures)
  * [verify (checksums)](#verify-checksums)
  * [trust](#trust)
  * [configure](#configure)
  * [clean](#clean)
* [Artifacts](#artifacts)

  * [sigmate.meta.json](#sigmatemetajson)
  * [sigmate.sbom.json](#sigmatesbomjson)
  * [checksum files](#checksum-files)
* [JSON output and exit codes](#json-output-and-exit-codes)
* [Security model](#security-model)
* [CI examples](#ci-examples)
* [License](#license)


## Install

Build from source:

```bash
git clone https://github.com/opensecurity/sigmate.git
cd sigmate
cargo build --release
# add target/release to your PATH
```

Install from cargo
```bash
cargo install sigmate
```

## Quick start

```bash
# Configure defaults once
sigmate configure

# Add a signer and mark verified after you vet it
sigmate trust add ./keys/alice.pub --name alice --added-by "Your Name"
sigmate trust update <alice_fingerprint> --status verified --updated-by "Your Name"

# Sign your project: raw .sig and metadata + SBOM
sigmate sign --walk . --both --sbom

# Verify with signer alias from keyring
sigmate verify --walk ./downloaded --signer alice --require-trusted --json
```


## Concepts

* Keyring: public keys stored by alias at `~/.config/sigmate/public_keys/`.
* Trust store: policy and audit at `~/.config/sigmate/trusted_public_keys.json`.

  * verification\_status: pending | verified | revoked | compromised
* Artifacts directory: `./signatures/` by default.
* Idempotent signing: existing valid signatures are skipped; mismatches fail unless `--force` is used.


## Usage

Run `sigmate --help` or `sigmate <command> --help` for all flags.

### sign

Generate Ed25519 signatures, metadata, SBOM, and/or checksum files.

```bash
# Recursively sign, produce .sig and metadata and SBOM
sigmate sign --walk . --both --sbom

# Single file with expiration in hours
sigmate sign ./release.tar.gz --both --expires-in 72

# Checksums only (no signing)
sigmate sign --walk . --gen-sha256sums

# Use a specific PEM private key (encrypted keys supported)
sigmate sign --walk . --both --key ./secrets/ed25519.pem --key-password-env SIGMATE_KEY_PASSPHRASE

# Output directory for artifacts
sigmate sign --walk . --both --signatures-output ./out/signatures

# Orphan scan and prune
sigmate sign --walk . --report-orphans
sigmate sign --walk . --prune-orphans -y
```

Key flags (subset):

* `--raw`, `--meta`, `--both`
* `--sbom`
* `--key PATH`, `--key-password-env ENV`
* `--signatures-output DIR`
* `--identity STR`, `--host STR`
* `--expires-in HOURS`
* `--no-abspath`
* `--gen-md5sums`, `--gen-sha1sums`, `--gen-sha256sums`, `--gen-sha512sums`
* `--force`
* `--report-orphans`, `--prune-orphans`, `-y`
* `--json`

### verify (signatures)

Verify using a public key path or a signer alias in the keyring.

```bash
# Use alias from keyring, enforce trust
sigmate verify --walk ./downloaded --signer alice --require-trusted

# Use a specific public key
sigmate verify --walk ./downloaded --key ./keys/alice.pub

# Machine readable output
sigmate verify --walk ./downloaded --signer alice --json
```

Signature source selection:

* `--sig-type auto|raw|meta` (default auto)
* Raw signatures are discovered at `./signatures/<file>.sig`
* Metadata is read from `./signatures/sigmate.meta.json`

### verify (checksums)

Verify against a checksum file (GNU or BSD format).

```bash
# Verify all entries from SHA256SUMS
sigmate verify --checksum-file ./SHA256SUMS --checksum-algo sha256

# Verify a specific file against a checksum file
sigmate verify ./artifact.zip --checksum-file ./SHA512SUMS --checksum-algo sha512

# JSON report
sigmate verify --checksum-file ./MD5SUMS --json
```

Flags:

* `--checksum-file FILE`
* `--checksum-algo auto|md5|sha1|sha256|sha512` (auto usually fine)
* `--checksum-format auto|gnu|bsd` (auto by default)

### trust

Manage trusted keys and the keyring.

```bash
# Add a key (stored as ~/.config/sigmate/public_keys/<name>.pub)
sigmate trust add ./keys/alice.pub --name alice --added-by "Your Name"

# List keys
sigmate trust list
sigmate trust list --json

# Update status
sigmate trust update <fingerprint> --status verified --updated-by "Your Name" --notes "manual verification"

# Remove from trust store (key file remains in keyring)
sigmate trust remove <fingerprint>
```

### configure

Set defaults interactively or non-interactively.

```bash
# Interactive
sigmate configure

# Non-interactive
sigmate configure \
  --private-key-path ./secrets/ed25519.pem \
  --signer-identity "Release Bot <bot@company.com>" \
  --keyring-path ~/.config/sigmate/public_keys
```

Environment overrides:

* `SIGMATE_PRIVATE_KEY_PATH`
* `SIGMATE_SIGNER_IDENTITY`
* `SIGMATE_KEYRING_PATH`

### clean

Remove generated artifacts with confirmation.

```bash
# Clean default ./signatures and default checksum files in CWD
sigmate clean

# Clean a specific artifact directory
sigmate clean ./out/signatures
```

Safety checks prevent deleting protected system paths.


## Artifacts

### sigmate.meta.json

Array of entries, one per signed file.

```json
[
  {
    "file": "Cargo.toml",
    "relpath": "Cargo.toml",
    "abspath": "/abs/path/to/Cargo.toml",
    "created_at": "2025-09-13T11:36:52Z",
    "expires_at": null,
    "tool": { "name": "sigmate", "version": "1.0.0", "language": "rust" },
    "signer_identity": "Lucian <42606+gni@users.noreply.github.com>",
    "signer_host": "core",
    "signature_algorithm": "Ed25519",
    "hash_algorithm": "sha256",
    "file_hash": "117d58ed208f72485b6e5f51cf59f3e66c7d3384e3f5d53c4a146537df8d78aa",
    "signature": "vvxBJB5CkCJnrGVUrHlUE/rbidF0hPQ3G/mqyebrB0VXumSCdFkowep2Rgw6A0464v1PQs4CyB0srCMYxCT7AA==",
    "signature_hash": "0e9aeccb0ff7eca1568e2ff322bf62a6997e1c527cbb4acafd603ce58c178ba5",
    "key_fingerprint": "4567c7758287a491f1eacd4f4149b51fcb8322bfa90daa63ab5575ed370bb7b2",
    "signature_file": "/abs/path/signatures/Cargo.toml.sig",
    "version": { "git": { "url": "https://github.com/opensecurity/sigmate", "ref": "heads/main-dirty" } }
  }
]
```

Notes:

* `abspath` is omitted when `--no-abspath` is used.
* `expires_at` is set when `--expires-in` is used.
* `version.git` is filled when the directory is a Git repo with an origin remote.

### sigmate.sbom.json

CycloneDX 1.5. Each signed file becomes a component with:

* SHA-256 hash
* Ed25519 signature
* properties:

  * `sigmate:relpath`
  * `sigmate:abspath` (omitted with `--no-abspath`)
* tool metadata with VCS references

### checksum files

GNU style:

```
01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b  myfile.zip
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 *empty file.txt
```

BSD style:

```
SHA256 (myfile.zip) = 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
MD5 (empty.txt) = d41d8cd98f00b204e9800998ecf8427e
```


## JSON output and exit codes

Most commands accept `--json`.

Verify (signatures) example:

```json
[
  {
    "file": "Cargo.lock",
    "metadata_source": "signatures/sigmate.meta.json",
    "valid_signature": true,
    "expired": false,
    "trusted_signer": true,
    "expected_hash": "1b0fefdb1e1ef6cda0ff3a340490379b94d1a2fb53c51fc3bddcc3516bf443df",
    "actual_hash": "1b0fefdb1e1ef6cda0ff3a340490379b94d1a2fb53c51fc3bddcc3516bf443df",
    "overall_verified": true
  }
]
```

Exit codes:

* 0: success
* 1: failure (verification mismatch, etc.)
* 2: user aborted or idempotency failure requiring `--force`


## Security model

* Ed25519 only for signing and verification.
* Encrypted private keys supported. Provide passphrase via `--key-password-env ENV` or interactively.
* Trust is explicit. `--require-trusted` enforces that the verifying key is present and marked `verified` in the trust store.
* Idempotency. Existing valid signatures are not overwritten unless `--force` is set.

## Authors
Lucian BLETAN

## License

MIT. See LICENSE.
