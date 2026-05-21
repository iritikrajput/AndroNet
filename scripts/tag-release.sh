#!/bin/bash
set -e
VERSION=$1
if [[ ! $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Usage: ./tag-release.sh X.Y.Z"
  exit 1
fi
TAG="v$VERSION"
echo "Creating release $TAG..."
git tag -a $TAG -m "Release $TAG"
git push origin $TAG
echo "Tag $TAG pushed. GitHub Actions will build and publish the APK."
echo "Monitor: https://github.com/amibhai/AndroNet/actions"
