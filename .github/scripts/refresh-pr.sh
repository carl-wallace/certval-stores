#!/usr/bin/env bash
# Opens the pull request for a refresh whose material moved, on a branch named for the crate.
#
# Usage: refresh-pr.sh BRANCH TITLE BODY_FILE PATH...
#   BRANCH     one per crate (refresh/<crate>), not per day, so material that keeps moving
#              produces one pull request rather than one a day
#   TITLE      the commit subject and the pull request title
#   BODY_FILE  what moved and how to review it: the commit body and the pull request description
#   PATH...    what the refresh writes; nothing else is staged
#
# Needs GH_TOKEN with contents and pull-requests write, and the repository setting that lets
# Actions create pull requests. IGNORE_LINES, one regex per line, names lines that
# change on every run (a snapshot date) and so do not count as the material moving.
#
# When a pull request from BRANCH is already open, nothing is pushed: it is under review, and
# the reviewer may have pushed to it (the pinned counts and set digests). If the material has
# moved again since, the pull request gets one comment saying so, and the next run after it is
# merged opens a new one for the rest.
#
# A pull request opened with the workflow's token starts no workflow, so the new pull request
# shows no checks. CI runs when the reviewer pushes the updated pinned counts and digests, which
# it would fail without. A refresh that needs no such update gets its CI by closing and
# reopening the pull request.
set -euo pipefail

branch=$1
title=$2
body=$3
shift 3

ignore=()
while IFS= read -r re; do
    [ -n "$re" ] && ignore+=(-I "$re")
done <<< "${IGNORE_LINES:-}"

git config user.name  "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"

open=$(gh pr list --head "$branch" --state open --json number --jq '.[0].number // empty')
if [ -n "$open" ]; then
    git fetch --depth=1 origin "+refs/heads/$branch:refs/remotes/origin/$branch"
    git add -- "$@"
    if git diff --cached --quiet "${ignore[@]}" "origin/$branch" -- "$@"; then
        echo "#$open already carries this material"
        exit 0
    fi
    digest=$(git diff --cached "${ignore[@]}" "origin/$branch" -- "$@" \
                 | { grep -v -E '^(diff|index) ' || true; } | sha256sum | cut -c1-16)
    comments=$(gh pr view "$open" --json comments --jq '.comments[].body')
    if [[ $comments == *"refresh-digest: $digest"* ]]; then
        echo "#$open already has a comment for this material"
        exit 0
    fi
    {
        echo "The material moved again since this pull request was opened. Merging this one"
        echo "leaves the rest for the next run, which opens a new pull request for it."
        echo
        cat "$body"
        echo
        echo "<!-- refresh-digest: $digest -->"
    } > "$RUNNER_TEMP/comment.md"
    gh pr comment "$open" --body-file "$RUNNER_TEMP/comment.md"
    exit 0
fi

base=$(gh repo view --json defaultBranchRef --jq .defaultBranchRef.name)
git checkout -B "$branch"
git add -- "$@"
{ echo "$title"; echo; cat "$body"; } | git commit -F -
# Forced: a branch left over from a merged or closed pull request is stale by definition.
git push --force origin "$branch"
gh pr create --base "$base" --head "$branch" --title "$title" --body-file "$body"
