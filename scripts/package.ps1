$ErrorActionPreference = "Stop"

$version = if ($env:VERSION) { $env:VERSION } else { "0.1.7" }
$goos = if ($env:GOOS) { $env:GOOS } else { (go env GOOS) }
$goarch = if ($env:GOARCH) { $env:GOARCH } else { (go env GOARCH) }
$ext = if ($goos -eq "windows") { ".dll" } elseif ($goos -eq "darwin") { ".dylib" } else { ".so" }
$pluginFile = Join-Path "dist" (Join-Path $goos (Join-Path $goarch ("diagnostics$ext")))
$packageDir = "release"
$zipFile = Join-Path $packageDir ("diagnostics_$version`_$goos`_$goarch.zip")

& "$PSScriptRoot\build.ps1"
New-Item -ItemType Directory -Force -Path $packageDir | Out-Null
if (Test-Path -LiteralPath $zipFile) {
  Remove-Item -LiteralPath $zipFile -Force
}
Compress-Archive -LiteralPath $pluginFile -DestinationPath $zipFile
Write-Host "Packaged $zipFile"
