#!/usr/bin/env bash
#
# Automates the release steps this project does by hand:
#   1. bump <version> in com_muruguard/muruguard.xml
#   2. verify CHANGELOG.md has a matching entry (this is what GitHub
#      Actions uses as the release notes -- see .github/workflows/release.yml)
#   3. remove a stray local build zip if one is sitting in the repo root
#   4. commit, push, tag, push the tag
#
# GitHub Actions takes it from there: builds the installable zip and
# publishes the GitHub Release using the CHANGELOG.md entry as the body.
#
# Usage: scripts/release.sh 2.1.7

set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>   e.g. $0 2.1.7" >&2
  exit 1
fi
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: version must look like X.Y.Z (got: $VERSION)" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MANIFEST="com_muruguard/muruguard.xml"
CHANGELOG="CHANGELOG.md"
TAG="v$VERSION"

if [[ "$(git branch --show-current)" != "main" ]]; then
  echo "Error: releases are cut from main (currently on $(git branch --show-current))." >&2
  exit 1
fi

if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "Error: tag $TAG already exists." >&2
  exit 1
fi

if ! grep -qE "^## \[$VERSION\]" "$CHANGELOG"; then
  echo "Error: $CHANGELOG has no '## [$VERSION]' section yet." >&2
  echo "Add one first (move the relevant entries out of [Unreleased] into it) -- this is what becomes the GitHub release description." >&2
  exit 1
fi

CURRENT_VERSION="$(grep -oE '<version>[^<]+</version>' "$MANIFEST" | sed -E 's#</?version>##g')"
if [[ "$CURRENT_VERSION" == "$VERSION" ]]; then
  echo "Note: $MANIFEST is already at $VERSION."
else
  echo "Bumping $MANIFEST: $CURRENT_VERSION -> $VERSION"
  sed -i.bak -E "s#<version>[^<]+</version>#<version>$VERSION</version>#" "$MANIFEST"
  rm -f "$MANIFEST.bak"
fi

# This project has a habit of accidentally committing a local build zip --
# make sure one isn't sitting in the repo root before releasing.
if [[ -f "com_muruguard.zip" ]]; then
  echo "Removing stray com_muruguard.zip"
  rm -f "com_muruguard.zip"
fi

# Refuse to sweep in unrelated work into the release commit -- only the
# manifest/changelog (and the stray-zip removal above) should be dirty at
# this point. Everything else should already be committed on its own.
DIRTY_OTHER="$(git status --porcelain -- . ":!$MANIFEST" ":!$CHANGELOG" ":!com_muruguard.zip")"
if [[ -n "$DIRTY_OTHER" ]]; then
  echo "Error: there are other uncommitted changes -- commit or stash them first:" >&2
  echo "$DIRTY_OTHER" >&2
  exit 1
fi

git add "$MANIFEST" "$CHANGELOG"
if git diff --cached --quiet; then
  echo "Note: $MANIFEST/$CHANGELOG already match $VERSION and are already committed -- nothing new to commit here."
else
  git commit -m "Release v$VERSION"
fi
git push origin main

git tag -a "$TAG" -m "Release $TAG"
git push origin "$TAG"

echo ""
echo "Pushed $TAG -- GitHub Actions will build the zip and publish the release:"
echo "  https://github.com/zkrana/joomla-security-scanner/actions"
