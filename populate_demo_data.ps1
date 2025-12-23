# Demo data population script for ElasMISP (Windows)
# Usage: .\populate_demo_data.ps1

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptPath

Set-Location $projectRoot

Write-Host "ElasMISP Demo Data Population" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""

# Check if environment file exists
if (-not (Test-Path ".env")) {
    Write-Host "Error: .env file not found!" -ForegroundColor Red
    Write-Host "Please create a .env file with DEMO_DATA_ENABLED=true" -ForegroundColor Yellow
    exit 1
}

# Run the demo data script
Write-Host "Running demo data generation script..." -ForegroundColor Green
python scripts/demo_data.py

exit $LASTEXITCODE
