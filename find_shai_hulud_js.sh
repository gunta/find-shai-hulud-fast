#!/usr/bin/env bash

# 注意:
#   このスクリプトはroot配下のファイル・フォルダを探索するため「システムに負荷がかかる場合があります」
#   実行は自己責任でお願いします。
# 使い方:
#   管理者権限でこのスクリプトを実行してください。
# Usage: ./scan_bundle.sh <start_directory>

set -u

TARGET_HASH="46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"


read -r -p "Do you understand that this process may put load on the system? [y/n] " ans


if [[ "${ans}" != "y" && "${ans}" != "Y" ]]; then
  echo "Aborted."
  exit 0
fi


if [[ $# -lt 1 || ! -d "$1" ]]; then
  echo "Error: please provide an existing directory as the first argument."
  echo "Usage: $0 <start_directory>"
  exit 1
fi
start_dir="$1"

sha_cmd=""
if command -v sha256sum >/dev/null 2>&1; then
  sha_cmd="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  sha_cmd="shasum -a 256"
else
  echo "Error: neither 'sha256sum' nor 'shasum' is available on this system."
  exit 1
fi

# 3) Find node_modules directories under the first arg
# 4) Within each node_modules, find bundle.js files
# 5) Compute SHA-256 and
# 6) If it matches TARGET_HASH, print path and hash
found_any=0
matches=0

# Find node_modules dirs (null-delimited to handle spaces/newlines)
while IFS= read -r -d '' nm_dir; do
  found_any=1
  # Search for bundle.js inside this node_modules
  while IFS= read -r -d '' bundle_file; do
    # Compute SHA256
    file_hash="$($sha_cmd "$bundle_file" | awk '{print $1}')"
    if [[ "$file_hash" == "$TARGET_HASH" ]]; then
      echo "MATCH: $bundle_file -> $file_hash"
      matches=$((matches+1))
    fi
  done < <(find "$nm_dir" -type f -name 'bundle.js' -print0)
done < <(find "$start_dir" -type d -name 'node_modules' -print0)

# Optional summary
if [[ $found_any -eq 0 ]]; then
  echo "No 'node_modules' directories found under: $start_dir"
elif [[ $matches -eq 0 ]]; then
  echo "No bundle.js files matched the target hash."
fi
