#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/render-homebrew-formula.sh \
    --owner <github-owner> \
    --repo <github-repo> \
    --version <semver-without-v> \
    --sha256 <source-tarball-sha256> \
    [--output <formula-path>]

Example:
  scripts/render-homebrew-formula.sh \
    --owner acme \
    --repo prehook \
    --version 0.1.0 \
    --sha256 0123...abcd
EOF
}

owner=""
repo=""
version=""
sha256=""
template="packaging/homebrew/prehook.rb.tmpl"
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
    --sha256)
      sha256="${2:-}"
      shift 2
      ;;
    --output)
      output="${2:-}"
      shift 2
      ;;
    --template)
      template="${2:-}"
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

if [[ -z "$owner" || -z "$repo" || -z "$version" || -z "$sha256" ]]; then
  echo "Missing required arguments." >&2
  usage >&2
  exit 1
fi

if [[ ! -f "$template" ]]; then
  echo "Formula template not found: $template" >&2
  exit 1
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

sed \
  -e "s/__OWNER__/${owner}/g" \
  -e "s/__REPO__/${repo}/g" \
  -e "s/__VERSION__/${version}/g" \
  -e "s/__SHA256__/${sha256}/g" \
  "$template" > "$tmp"

mv "$tmp" "$output"
echo "Rendered formula: $output"
