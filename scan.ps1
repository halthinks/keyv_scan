[CmdletBinding()]
param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]] $ScannerArguments
)
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Node = Get-Command node -ErrorAction SilentlyContinue
if (-not $Node) {
  Write-Error 'Node.js 18 or newer is required.'
  exit 2
}
$NodeVersion = (& $Node.Source -p "process.versions.node").Trim()
$NodeMajor = [int]($NodeVersion.Split('.')[0])
if ($NodeMajor -lt 18) {
  Write-Error "Node.js 18 or newer is required; found $NodeVersion."
  exit 2
}
& $Node.Source (Join-Path $ScriptDir 'bin\keyv-scan.js') scan @ScannerArguments
exit $LASTEXITCODE
