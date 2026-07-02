$ErrorActionPreference = "Stop"

$version = if ($env:VERSION) { $env:VERSION } else { "0.1.8" }
$goos = if ($env:GOOS) { $env:GOOS } else { (go env GOOS) }
$goarch = if ($env:GOARCH) { $env:GOARCH } else { (go env GOARCH) }
$ext = if ($goos -eq "windows") { ".dll" } elseif ($goos -eq "darwin") { ".dylib" } else { ".so" }
$pluginID = "cpa-network-diagnostics-plugin"
$pluginFile = Join-Path "dist" (Join-Path $goos (Join-Path $goarch ("diagnostics$ext")))
$packageDir = "release"
$zipFile = Join-Path $packageDir ("$pluginID`_$version`_$goos`_$goarch.zip")
$zipRoot = Join-Path $packageDir "zip-root"
$packagedPluginFile = Join-Path $zipRoot ("$pluginID$ext")

& "$PSScriptRoot\build.ps1"
New-Item -ItemType Directory -Force -Path $packageDir | Out-Null
if (Test-Path -LiteralPath $zipFile) {
  Remove-Item -LiteralPath $zipFile -Force
}
if (Test-Path -LiteralPath $zipRoot) {
  Remove-Item -LiteralPath $zipRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $zipRoot | Out-Null
Copy-Item -LiteralPath $pluginFile -Destination $packagedPluginFile -Force
Compress-Archive -LiteralPath $packagedPluginFile -DestinationPath $zipFile
Remove-Item -LiteralPath $zipRoot -Recurse -Force
Write-Host "Packaged $zipFile"
