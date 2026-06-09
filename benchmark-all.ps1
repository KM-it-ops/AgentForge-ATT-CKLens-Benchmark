$ErrorActionPreference = "Continue"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = "python"
$Helper = Join-Path $RepoRoot "tools\evaluate_branches.py"

Write-Host "AgentForge ATT&CKLens benchmark evaluation"
Write-Host "Repository: $RepoRoot"

if (-not (Test-Path -LiteralPath $Helper)) {
    Write-Error "Missing evaluator helper: $Helper"
    exit 1
}

Push-Location $RepoRoot
try {
    & $Python $Helper --repo $RepoRoot
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Logs saved to: evaluations\logs"
Write-Host "Scorecards saved to: evaluations\scorecards"
Write-Host "Raw outputs saved to: evaluations\raw-outputs"
Write-Host "Notes saved to: evaluations\notes"
Write-Host "Final report saved to: evaluations\final\final-report.md"

exit $exitCode
