#!/usr/bin/env bash
# Usage: check-trailers.sh <rev-range>   — verifies AWS trailer contract on every non-merge commit.
set -euo pipefail
RANGE="${1:?usage: check-trailers.sh <rev-range>}"
FAIL=0
for SHA in $(git rev-list --no-merges "$RANGE"); do
  CHANGE=$(git log -1 --format='%(trailers:key=AWS-Change,valueonly,separator=)' "$SHA" | head -1)
  COMPONENT=$(git log -1 --format='%(trailers:key=AWS-Component,valueonly,separator=)' "$SHA" | head -1)
  USTATUS=$(git log -1 --format='%(trailers:key=Upstream-Status,valueonly,separator=)' "$SHA" | head -1)
  ERR=""
  case "$CHANGE" in feature|fix|backport|build|revert) ;; *) ERR+=" AWS-Change missing/invalid ('$CHANGE');" ;; esac
  case "$COMPONENT" in cortex|prometheus|thanos|promql-engine|alertmanager|gomemcache) ;; *) ERR+=" AWS-Component missing/invalid ('$COMPONENT');" ;; esac
  case "$USTATUS" in none|submitted|merged|rejected) ;; *) ERR+=" Upstream-Status missing/invalid ('$USTATUS');" ;; esac
  if [ -n "$ERR" ]; then
    echo "FAIL $SHA:$ERR"
    echo "     subject: $(git log -1 --format=%s "$SHA")"
    FAIL=1
  fi
done
if [ "$FAIL" = 1 ]; then
  cat <<'HELP'
Every commit needs trailers, e.g.:
    AWS-Change: fix
    AWS-Component: promql-engine
    Upstream-Status: none
(Optional: Upstream-PR: <url>, Issue: PROMET-1234, AWS-Owner: alias)
HELP
  exit 1
fi
echo "trailer-lint: all commits OK"
