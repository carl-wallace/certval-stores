#!/usr/bin/env bash
# What moved in each CBOR store a refresh rewrote, for the commit message of the branch it pushes.
#
#   store-diff.sh <crate-dir> [cargo args for certval-store-gen, e.g. --features cli]
#
# For every .cbor under <crate-dir> that differs from HEAD, prints the store's path and then
# `certval-store-gen diff` of the committed version against the working one: certificates added and
# removed by subject, issuer and serial, and how many partial paths moved. A store that is new prints
# as such. Prints nothing when no store changed, which is the case for a provider that commits
# certificates rather than a store.
#
# The cargo arguments are the ones the calling job already built the tool with, so running the diff
# reuses that build rather than compiling the tool again with a different feature set.
set -euo pipefail

crate="$1"
shift

scratch="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"

# `git status`, not `git diff`: a store the refresh created for the first time is untracked, and a
# diff would not list it. The first three columns are the status and a space.
stores=$(git status --porcelain -- "$crate" | cut -c4- | grep '\.cbor$' || true)

for store in $stores; do
  if git cat-file -e "HEAD:$store" 2>/dev/null; then
    git show "HEAD:$store" > "$scratch/store-diff-before.cbor"
    echo "$store:"
    cargo run -q -p certval-store-gen "$@" -- diff "$scratch/store-diff-before.cbor" "$store" \
      | sed 's/^/  /'
  else
    echo "$store: a new store"
  fi
done
