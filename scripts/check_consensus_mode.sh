#!/usr/bin/env sh
set -eu

mode="${GREENHOUSE_CONSENSUS_MODE:-}"

if [ -z "$mode" ]; then
  echo "ERROR: GREENHOUSE_CONSENSUS_MODE is required and must be 'http' or 'dbft'." >&2
  exit 1
fi

case "$mode" in
  http|dbft)
    echo "Consensus mode validated: $mode"
    ;;
  *)
    echo "ERROR: invalid GREENHOUSE_CONSENSUS_MODE='$mode' (expected 'http' or 'dbft')." >&2
    exit 1
    ;;
esac
