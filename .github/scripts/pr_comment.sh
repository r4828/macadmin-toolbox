#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Robert Flanagan and macadmin-toolbox contributors
# SPDX-License-Identifier: MIT
#
# Name:      pr_comment.sh
# Purpose:   Post a CI report to a pull request as a single comment, edited in
#            place on each push rather than added to.
# Context:   Runs from .github/workflows/lint.yml. From the repo root:
#            PR_NUMBER=1 GH_TOKEN=... .github/scripts/pr_comment.sh report.md
# Tested on: bash 3.2 (macOS), bash 5 (Ubuntu CI runners)
#
# A run that reported by appending would bury the current state under the
# history of getting there, so this finds its own previous comment and rewrites
# it.
#
# Hand-rolled against the REST API rather than a marketplace action. The usual
# comment actions publish amd64-only Docker images and cannot execute on an
# arm64 runner, so the same script would not be portable to the self-hosted
# boxes the sibling repositories use; curl and jq are everywhere.
#
# Usage: pr_comment.sh <report-file>
#
# Required environment:
#   GH_TOKEN            token carrying `pull-requests: write`
#   GITHUB_REPOSITORY   owner/repo, set by Actions
#   PR_NUMBER           the pull request to comment on
#
# Optional environment:
#   CI_COMMENT_MARKER   hidden marker identifying which comment to reuse; give
#                       each workflow its own value if a repository posts more
#                       than one report to the same pull request
#   RUN_URL             linked at the foot of the comment
#   GITHUB_API_URL      set by Actions; overridden only on GitHub Enterprise
set -euo pipefail

REPORT_FILE="${1:-}"
if [ -z "$REPORT_FILE" ]; then
  echo "usage: $0 <report-file>" >&2
  exit 2
fi

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${PR_NUMBER:?PR_NUMBER is required}"

MARKER="${CI_COMMENT_MARKER:-<!-- ci-report -->}"
API="${GITHUB_API_URL:-https://api.github.com}/repos/${GITHUB_REPOSITORY}"

# GitHub rejects a comment body over 65536 characters outright, so an unbounded
# report posts nothing at all on exactly the runs worth reporting -- the ones
# with hundreds of findings. Truncation is on a line boundary because cutting
# mid-line splits a table row or a fenced block and corrupts the rest.
MAX_CHARS=60000

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

# The token goes in a curl config file, not an argv header. A self-hosted
# runner is a persistent host that runs several repositories' jobs, and an
# argument vector is readable by anything else running at the same time.
umask 077
authcfg="$workdir/auth"
printf 'header = "Authorization: Bearer %s"\n' "$GH_TOKEN" > "$authcfg"

# No --location: a redirect would resend the Authorization header to whatever
# host the redirect names.
api() {
  curl --silent --show-error --fail \
    --config "$authcfg" \
    --header "Accept: application/vnd.github+json" \
    --header "X-GitHub-Api-Version: 2022-11-28" \
    "$@"
}

body="$workdir/body.md"
{
  printf '%s\n' "$MARKER"
  if [ -s "$REPORT_FILE" ]; then
    awk -v max="$MAX_CHARS" '
      { n += length($0) + 1 }
      n > max { print ""; print "_Report truncated. The run page has all of it._"; exit }
      { print }
    ' "$REPORT_FILE"
  else
    printf '\nThe run produced no report. See the run log.\n'
  fi
  if [ -n "${RUN_URL:-}" ]; then
    printf '\n---\n\n[Full run page](%s)\n' "$RUN_URL"
  fi
} > "$body"

# Paginated deliberately. The comments endpoint returns 30 per page by default
# and caps at 100, so a long-running pull request hides its own report comment
# past the first page -- and a report that cannot be found is a report that
# gets posted again from scratch every push.
comment_id=""
page=1
while [ "$page" -le 10 ]; do
  if ! api "${API}/issues/${PR_NUMBER}/comments?per_page=100&page=${page}" > "$workdir/page.json"; then
    echo "could not list comments on #${PR_NUMBER}" >&2
    exit 1
  fi
  comment_id=$(jq -r --arg m "$MARKER" \
    'map(select((.body // "") | startswith($m))) | .[0].id // empty' < "$workdir/page.json")
  if [ -n "$comment_id" ]; then
    break
  fi
  if [ "$(jq 'length' < "$workdir/page.json")" -lt 100 ]; then
    break
  fi
  page=$((page + 1))
done

# jq builds the JSON so the body is escaped by something that knows the format.
# The report is Markdown containing quotes, backslashes and newlines; a
# hand-built payload breaks on the first finding that mentions one.
jq -Rs '{body: .}' < "$body" > "$workdir/payload.json"

if [ -n "$comment_id" ]; then
  api --request PATCH \
    --header "Content-Type: application/json" \
    --data @"$workdir/payload.json" \
    "${API}/issues/comments/${comment_id}" > /dev/null
  echo "updated comment ${comment_id} on #${PR_NUMBER}"
else
  api --request POST \
    --header "Content-Type: application/json" \
    --data @"$workdir/payload.json" \
    "${API}/issues/${PR_NUMBER}/comments" > /dev/null
  echo "posted a new comment on #${PR_NUMBER}"
fi
