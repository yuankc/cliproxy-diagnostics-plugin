#!/usr/bin/env bash
set -euo pipefail

version="${VERSION:-0.1.10}"
goos="${GOOS:-$(go env GOOS)}"
goarch="${GOARCH:-$(go env GOARCH)}"
plugin_id="cpa-network-diagnostics-plugin"
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
zip_file="$package_dir/${plugin_id}_${version}_${goos}_${goarch}.zip"
zip_root="$package_dir/zip-root"
packaged_plugin_file="$zip_root/${plugin_id}${ext}"

bash "$script_dir/build.sh"
mkdir -p "$package_dir"
rm -f "$zip_file"
rm -rf "$zip_root"
mkdir -p "$zip_root"
cp "$plugin_file" "$packaged_plugin_file"
(
  cd "$zip_root"
  zip -q "$zip_file" "$(basename "$packaged_plugin_file")"
)
rm -rf "$zip_root"
echo "Packaged $zip_file"
