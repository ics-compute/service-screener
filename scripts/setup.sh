#!/usr/bin/env bash
# Set up the aws-svc-screener Kiro skill (Linux / macOS).
#
# This repo IS the Kiro skill: clone it to <workspace>/.kiro/skills/aws-svc-screener
# (or ~/.kiro/skills/aws-svc-screener for a global install), then run from the skill root:
#   bash scripts/setup.sh
#
# Works from any cwd (paths are resolved from this script's location). Takes no arguments.
# Idempotent: safe to re-run, it reuses an existing .venv.
#
# What this script does:
#   1. Creates (or reuses) a Python venv at <skill root>/.venv
#   2. Installs requirements.txt into it
set -euo pipefail

# ── Path resolution ───────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # <repo>/scripts/
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"                    # <repo>/ (contains main.py, requirements.txt, …)

# ── Step 1: Validate tool files ───────────────────────────────────────────────
for f in main.py requirements.txt; do
  if [ ! -f "$REPO_ROOT/$f" ]; then
    echo "error: '$REPO_ROOT/$f' not found." >&2
    echo "Run this script from a full clone of the service-screener repo (scripts/setup.sh inside it)." >&2
    exit 1
  fi
done

# ── Step 2: Python ────────────────────────────────────────────────────────────
command -v python3 >/dev/null 2>&1 || {
  echo "error: python3 is not on PATH. Install Python 3.13 (3.12 has worked in practice) first." >&2
  exit 1
}

PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
echo "Using python3 ${PY_VERSION} ($(command -v python3))"
case "$PY_VERSION" in
  3.13|3.12) ;;
  *) echo "warning: Service Screener v2 targets Python 3.13 (3.12 has worked in practice). Continuing anyway." >&2 ;;
esac

# ── Step 3: Python venv ───────────────────────────────────────────────────────
VENV_DIR="$REPO_ROOT/.venv"
VENV_PY="$VENV_DIR/bin/python"
if [ -d "$VENV_DIR" ]; then
  if [ ! -x "$VENV_PY" ]; then
    echo "error: '$VENV_DIR' exists but '$VENV_PY' is missing (broken or non-Linux/macOS venv)." >&2
    echo "Delete '$VENV_DIR' and re-run this script." >&2
    exit 1
  fi
  echo "==> Reusing existing venv at $VENV_DIR"
else
  echo "==> Creating venv at $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

echo "==> Installing Python dependencies from requirements.txt"
"$VENV_PY" -m pip install --upgrade pip >/dev/null
# requirements.txt ends with "-e ." (editable install of this repo), which pip resolves
# relative to cwd, not the file's location — so it must run from the repo root.
( cd "$REPO_ROOT" && "$VENV_PY" -m pip install -r requirements.txt )

if command -v aws >/dev/null 2>&1; then
  echo "==> AWS CLI found: $(aws --version 2>&1)"
else
  echo "warning: AWS CLI not found on PATH. You can still run scans if boto3 picks up credentials another way (env vars, IAM role), but 'aws sts get-caller-identity' won't be available to confirm the target account first." >&2
fi

cat <<EOF

Setup complete.
  Skill / tool root:  $REPO_ROOT
  Venv:               $VENV_DIR

Optional — only if you want the beta Cloudscape UI (--beta 1):
  cd "$REPO_ROOT/cloudscape-ui" && npm ci && npm run build && cd -
  (requires Node ^20.19.0 or >=22.12.0)

Update later:
  git -C "$REPO_ROOT" pull
  then re-run 'bash scripts/setup.sh' if requirements.txt changed,
  and rebuild cloudscape-ui if you use --beta 1.

Next: confirm your AWS profile, then ask Kiro to run a scan, e.g.
  /aws-svc-screener scan ap-southeast-1 with profile <your-profile>

Note: the Lambda deprecated-runtime check is currently skipped in this layout
("Skipped runtime version check..." in the scan output is expected).
EOF
