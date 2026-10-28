#!/usr/bin/env bash
# The trust anchors a refresh added, removed or replaced, for the description of the pull request
# it opens.
#
#   roots-diff.sh <crate-dir>
#
# A refresh rewrites a crate's roots/ wholesale, so a file that appears, disappears or changes
# there is an anchor the publisher added, dropped or re-issued. Each is named by file and subject;
# a removed one's subject is read from HEAD. Prints nothing when no root moved.
#
# `git status -z`, not a word-split list: TPM root files have spaces in their names. And
# --untracked-files=all, so a root added to a directory that is itself new is listed by file.
set -euo pipefail

crate="$1"

subject() {
  openssl x509 -inform DER -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//' \
    || echo "<does not parse as a certificate>"
}

lines=()
while IFS= read -r -d '' entry; do
  status="${entry:0:2}"
  path="${entry:3}"
  case "$path" in
    *.der) ;;
    *) continue ;;
  esac
  case "$status" in
    "??" | "A " | " A") lines+=("- added \`$path\`: $(subject < "$path")") ;;
    "D " | " D") lines+=("- removed \`$path\`: $(git show "HEAD:$path" | subject)") ;;
    *) lines+=("- replaced \`$path\`: $(subject < "$path")") ;;
  esac
done < <(git status --porcelain -z --untracked-files=all -- "$crate/roots")

if [ "${#lines[@]}" -eq 0 ]; then
  exit 0
fi

echo "Trust anchors changed. Each is a trust decision by the publisher, and the reason for the"
echo "minor version bump suggested above. The embedded root list was regenerated with them."
echo
printf '%s\n' "${lines[@]}"
