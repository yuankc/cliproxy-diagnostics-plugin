#!/usr/bin/env bash
set -euo pipefail

version="${VERSION:-0.1.7}"
goos="${GOOS:-$(go env GOOS)}"
goarch="${GOARCH:-$(go env GOARCH)}"
ext=".so"
if [[ "$goos" == "darwin" ]]; then
  ext=".dylib"
elif [[ "$goos" == "windows" ]]; then
  ext=".dll"
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
plugin_file="$repo_dir/dist/$goos/$goarch/diagnostics$ext"
package_dir="$repo_dir/release"
zip_file="$package_dir/diagnostics_${version}_${goos}_${goarch}.zip"

bash "$script_dir/build.sh"
mkdir -p "$package_dir"
rm -f "$zip_file"
(
  cd "$(dirname "$plugin_file")"
  zip -q "$zip_file" "$(basename "$plugin_file")"
)
echo "Packaged $zip_file"
