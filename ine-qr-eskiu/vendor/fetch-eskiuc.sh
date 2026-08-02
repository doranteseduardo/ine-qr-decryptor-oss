#!/usr/bin/env bash
# fetch-eskiuc.sh — download the Linux x86-64 Eskiu compiler at build time.
#
# The Eskiu compiler (`eskiuc`) is published as a release asset in the public
# repo https://github.com/doranteseduardo/eskiu. We fetch it here instead of
# vendoring the ~22 MB binary in git.
#
# Usage:
#   ine-qr-eskiu/vendor/fetch-eskiuc.sh            # uses ESKIUC_VERSION below
#   ESKIUC_VERSION=v0.6.1 ine-qr-eskiu/vendor/fetch-eskiuc.sh
#
# Writes ./eskiuc-linux-x86_64.tar.gz next to this script. The Dockerfile
# extracts it to /opt (bin/eskiuc + lib/eskiu/stdlib).
set -euo pipefail
cd "$(dirname "$0")"

REPO="doranteseduardo/eskiu"
ASSET="eskiuc-linux-x86_64.tar.gz"

# TODO(eduardo): confirm the exact release tag + asset naming once the public
# `eskiu` repo is live. The eskiu port in this tree targets eskiuc 0.6.1, so a
# tag like v0.6.1 is the expected default — adjust if the release scheme differs.
ESKIUC_VERSION="${ESKIUC_VERSION:-v0.6.1}"

OUT="$ASSET"

echo "Fetching $ASSET from $REPO @ $ESKIUC_VERSION ..."

if command -v gh >/dev/null 2>&1; then
  gh release download "$ESKIUC_VERSION" --repo "$REPO" -p "$ASSET" -O "$OUT" --clobber
else
  URL="https://github.com/${REPO}/releases/download/${ESKIUC_VERSION}/${ASSET}"
  echo "gh CLI not found; downloading via curl: $URL"
  curl -fsSL "$URL" -o "$OUT"
fi

echo "Wrote $(pwd)/$OUT"
