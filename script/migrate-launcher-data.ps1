# Remove this compatibility migration in v0.53.0.
function Get-LauncherDataRoot {
  $xdg = $env:XDG_DATA_HOME
  if ($xdg -and ($xdg -match '^([A-Za-z]:[\\/]|\\\\)')) {
    return (Join-Path $xdg 'autolith-launcher')
  }
  if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA is not set.' }
  return (Join-Path $env:LOCALAPPDATA 'autolith-launcher\data')
}

function Move-LegacyLauncherData {
  $xdg = $env:XDG_DATA_HOME
  if ($xdg -and ($xdg -match '^([A-Za-z]:[\\/]|\\\\)')) {
    $oldRoot = Join-Path $xdg 'autolith'
  } else {
    $oldRoot = Join-Path $env:LOCALAPPDATA 'autolith\data'
  }
  $newRoot = Get-LauncherDataRoot
  foreach ($root in @($oldRoot, $newRoot)) {
    $item = Get-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue
    if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw "launcher data root $root is a symbolic link."
    }
  }
  if (-not (Test-Path -LiteralPath $oldRoot -PathType Container)) { return }
  New-Item -ItemType Directory -Force -Path $newRoot | Out-Null
  foreach ($name in @('active', 'recovery', 'runtimes', 'recovery-worktrees',
                      'installation', 'nix', 'helpers', 'release-images')) {
    $source = Join-Path $oldRoot $name
    $target = Join-Path $newRoot $name
    $sourceItem = Get-Item -LiteralPath $source -Force -ErrorAction SilentlyContinue
    $targetItem = Get-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
    if (($sourceItem -and ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) -or
        ($targetItem -and ($targetItem.Attributes -band [IO.FileAttributes]::ReparsePoint))) {
      throw "launcher data directory $name is a symbolic link."
    }
    if ($sourceItem -and $targetItem) { throw "launcher data directory $name exists in both roots." }
    if ($sourceItem) { Move-Item -LiteralPath $source -Destination $target }
  }
  $oldNative = Join-Path $oldRoot 'native'
  $newNative = Join-Path $newRoot 'native'
  foreach ($path in @($oldNative, $newNative,
                     (Join-Path $oldNative 'sandbox'),
                     (Join-Path $newNative 'sandbox'))) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'native sandbox directory is a symbolic link.'
    }
  }
  $oldSandbox = Join-Path $oldNative 'sandbox'
  $newSandbox = Join-Path $newNative 'sandbox'
  if (Test-Path -LiteralPath $oldSandbox) {
    if (Test-Path -LiteralPath $newSandbox) { throw 'native sandbox exists in both roots.' }
    New-Item -ItemType Directory -Force -Path $newNative | Out-Null
    Move-Item -LiteralPath $oldSandbox -Destination $newSandbox
  }
}
