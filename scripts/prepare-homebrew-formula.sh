#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/prepare-homebrew-formula.sh \
    --owner <github-owner> \
    --repo <github-repo> \
    --version <semver-without-v> \
    [--output <formula-path>]

This script downloads the GitHub source tarball for v<version>,
computes sha256, and renders packaging/homebrew/prehook.rb.
EOF
}

owner=""
repo=""
version=""
output="packaging/homebrew/prehook.rb"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --owner)
      owner="${2:-}"
      shift 2
      ;;
    --repo)
      repo="${2:-}"
      shift 2
      ;;
    --version)
      version="${2:-}"
      shift 2
      ;;
    --output)
      output="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$owner" || -z "$repo" || -z "$version" ]]; then
  echo "Missing required arguments." >&2
  usage >&2
  exit 1
fi

archive_url="https://github.com/${owner}/${repo}/archive/refs/tags/v${version}.tar.gz"
echo "Fetching ${archive_url} for sha256..."

sha256="$(
  curl -fsSL "$archive_url" | shasum -a 256 | awk '{print $1}'
)"

scripts/render-homebrew-formula.sh \
  --owner "$owner" \
  --repo "$repo" \
  --version "$version" \
  --sha256 "$sha256" \
  --output "$output"

echo "sha256: $sha256"
echo "Formula ready: $output"
