$ErrorActionPreference = "Stop"

$goos = if ($env:GOOS) { $env:GOOS } else { (go env GOOS) }
$goarch = if ($env:GOARCH) { $env:GOARCH } else { (go env GOARCH) }
$version = if ($env:VERSION) { $env:VERSION } else { "0.1.13" }
$ext = if ($goos -eq "windows") { ".dll" } elseif ($goos -eq "darwin") { ".dylib" } else { ".so" }
$outDir = Join-Path "dist" (Join-Path $goos $goarch)
$outFile = Join-Path $outDir ("diagnostics$ext")

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$env:CGO_ENABLED = "1"
go build -buildmode=c-shared -trimpath -ldflags "-s -w -X main.pluginVersion=$version" -o $outFile .
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}
Write-Host "Built $outFile"

