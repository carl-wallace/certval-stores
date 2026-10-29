#!/usr/bin/env bash
# The version bump a refresh calls for under the providers' Versioning rule (each crate's README),
# for the description of the pull request it opens.
#
#   suggested-bump.sh <crate-dir>
#
# Minor when a store's trust anchors changed: a file under roots/ was added, removed or replaced,
# or a generated list that assigns roots to stores changed. The second matters on its own, because
# a root can leave a store while its file stays: when the Microsoft list withdraws a purpose, the
# root leaves that environment's env_*.rs and stays in msft_all. Patch otherwise, when only
# intermediate CA certificates, partial paths or dates moved.
set -euo pipefail

crate="$1"

if [ -n "$(git status --porcelain --untracked-files=all -- "$crate/roots" \
  ":(glob)$crate/src/roots_*.rs" ":(glob)$crate/src/env_*.rs")" ]; then
  echo "Suggested version bump: **minor**, because a store's trust anchors changed."
else
  echo "Suggested version bump: **patch**, because no store's trust anchors changed; only"
  echo "intermediate CA certificates, partial paths or dates did."
fi
