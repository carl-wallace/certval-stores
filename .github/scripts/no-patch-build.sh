#!/usr/bin/env bash
# Build the published crates the way a crates.io user resolves them: from their packaged .crate
# files, in a scratch workspace with no [patch] for anything but one another.
#
#   no-patch-build.sh
#
# This repository's [patch.crates-io] swaps in git versions of x509-ocsp, cmpv2, crmf, x509-tsp and
# authenticode for certval-store-gen. A user of a published crate gets none of that, so a published
# crate that came to rely on one of them would build here and fail for its users. Packaging writes
# the manifest a user receives; building those manifests on their own is the check. It is step 4 of
# MAINTENANCE.md's release checklist, run on every push instead of remembered at release time.
#
# The scratch workspace patches the published crates to one another, so an unreleased change to,
# say, certval_stores_provider_core is what the providers build against, as it will be once they are
# released together. Its lockfile is resolved fresh, which is also what a new user gets.
set -euo pipefail

crates=(
    certval_stores_provider_core
    certval_stores_core
    certval_stores_eca
    certval_stores_fpki
    certval_stores_msft
    certval_stores_nipr
    certval_stores_pbdev
    certval_stores_tpm
    certval_stores_wcf
    certval_stores_webpki_root_certs
)

root=$(git rev-parse --show-toplevel)
scratch=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/no-patch.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

cd "$root"
metadata=$(cargo metadata --no-deps --format-version 1)
members=""
patches=""
for crate in "${crates[@]}"; do
    version=$(printf '%s' "$metadata" | jq -r --arg n "$crate" '.packages[] | select(.name == $n) | .version')
    # --allow-dirty so a local run checks the working tree; CI's checkout is clean either way. This
    # never publishes, so nothing it packages leaves the machine.
    cargo package --no-verify --allow-dirty --quiet -p "$crate"
    tar -xzf "target/package/$crate-$version.crate" -C "$scratch"
    members="$members    \"$crate-$version\",\n"
    patches="$patches$crate = { path = \"$crate-$version\" }\n"
done

printf '[workspace]\nresolver = "2"\nmembers = [\n%b]\n\n[patch.crates-io]\n%b' \
    "$members" "$patches" > "$scratch/Cargo.toml"

cd "$scratch"
cargo build --workspace
cargo build --workspace --all-features
echo "The published crates build without this repository's [patch.crates-io]."
