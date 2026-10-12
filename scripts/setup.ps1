<#
.SYNOPSIS
  Set up the aws-svc-screener Kiro skill (Windows / PowerShell).

.DESCRIPTION
  This repo IS the Kiro skill: clone it to <workspace>\.kiro\skills\aws-svc-screener
  (or ~\.kiro\skills\aws-svc-screener for a global install), then run from the skill root.

  Works from any cwd (paths are resolved from this script's location). Takes no arguments.
  Idempotent: safe to re-run, it reuses an existing .venv.

  What this script does:
    1. Creates (or reuses) a Python venv at <skill root>\.venv
    2. Installs requirements.txt into it

.EXAMPLE
  # From the skill root
  powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
#>

$ErrorActionPreference = "Stop"

# ── Path resolution ───────────────────────────────────────────────────────────
$RepoRoot = Split-Path -Parent $PSScriptRoot   # repo root (has main.py, requirements.txt, …)

# ── Step 1: Validate tool files ───────────────────────────────────────────────
foreach ($f in @("main.py", "requirements.txt")) {
    if (-not (Test-Path (Join-Path $RepoRoot $f))) {
        throw "'$(Join-Path $RepoRoot $f)' not found. Run this script from a full clone of the service-screener repo (scripts\setup.ps1 inside it)."
    }
}

# ── Step 2: Python ────────────────────────────────────────────────────────────
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command py -ErrorAction SilentlyContinue }
if (-not $python) {
    throw "python (or the py launcher) is not on PATH. Install Python 3.13 (3.12 has worked in practice), e.g. 'winget install Python.Python.3.13'."
}

$pyVersion = & $python.Source -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ($LASTEXITCODE -ne 0) { throw "Failed to run '$($python.Source)' to detect the Python version." }
Write-Host "Using $($python.Source) (Python $pyVersion)"
if ($pyVersion -notin @("3.13", "3.12")) {
    Write-Warning "Service Screener v2 targets Python 3.13 (3.12 has worked in practice). Continuing anyway."
}

# ── Step 3: Python venv ───────────────────────────────────────────────────────
$VenvDir = Join-Path $RepoRoot ".venv"
$VenvPy  = Join-Path $VenvDir "Scripts\python.exe"
if (Test-Path $VenvDir) {
    if (-not (Test-Path $VenvPy)) {
        throw "'$VenvDir' exists but '$VenvPy' is missing (broken or non-Windows venv). Delete '$VenvDir' and re-run this script."
    }
    Write-Host "==> Reusing existing venv at $VenvDir"
} else {
    Write-Host "==> Creating venv at $VenvDir"
    & $python.Source -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) { throw "Failed to create venv at $VenvDir (exit code $LASTEXITCODE)." }
}

Write-Host "==> Installing Python dependencies from requirements.txt"
& $VenvPy -m pip install --upgrade pip | Out-Null
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed (exit code $LASTEXITCODE)." }
# requirements.txt ends with "-e ." (editable install of this repo), which pip resolves
# relative to cwd, not the file's location — so it must run from the repo root.
Push-Location $RepoRoot
try {
    & $VenvPy -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw "pip install -r requirements.txt failed (exit code $LASTEXITCODE)." }
} finally {
    Pop-Location
}

$aws = Get-Command aws -ErrorAction SilentlyContinue
if ($aws) {
    Write-Host "==> AWS CLI found: $(& aws --version 2>&1)"
} else {
    Write-Warning "AWS CLI not found on PATH. You can still run scans if boto3 picks up credentials another way (env vars, IAM role), but 'aws sts get-caller-identity' won't be available to confirm the target account first."
}

Write-Host ""
Write-Host "Setup complete."
Write-Host "  Skill / tool root:  $RepoRoot"
Write-Host "  Venv:               $VenvDir"
Write-Host ""
Write-Host "Optional -- only if you want the beta Cloudscape UI (--beta 1):"
Write-Host "  cd `"$RepoRoot\cloudscape-ui`"; npm ci; npm run build; cd .."
Write-Host "  (requires Node ^20.19.0 or >=22.12.0)"
Write-Host ""
Write-Host "Update later:"
Write-Host "  git -C `"$RepoRoot`" pull"
Write-Host "  then re-run 'scripts\setup.ps1' if requirements.txt changed,"
Write-Host "  and rebuild cloudscape-ui if you use --beta 1."
Write-Host ""
Write-Host "Next: confirm your AWS profile, then ask Kiro to run a scan, e.g."
Write-Host "  /aws-svc-screener scan ap-southeast-1 with profile <your-profile>"
Write-Host ""
Write-Host "Note: the Lambda deprecated-runtime check is currently skipped in this layout"
Write-Host "(`"Skipped runtime version check...`" in the scan output is expected)."
