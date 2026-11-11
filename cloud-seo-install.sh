#!/usr/bin/env bash
# Run with Bash from any directory; keep this file at the repository root.
set -euo pipefail
umask 077

die() { printf '%s\n' "$*" >&2; exit 1; }
skip_browser=()
case "${1:-}" in
    '') ;;
    --skip-browser) skip_browser=(--skip-browser) ;;
    *) die 'Usage: bash cloud-seo-install.sh [--skip-browser]' ;;
esac
(( $# <= 1 )) || die 'Too many arguments.'

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ "$repo_root" == /workspace/* ]] || die 'The checkout must be below /workspace.'
cd -- "$repo_root"
[[ -f requirements.txt && -f scripts/runtime.py && -x scripts/claude-seo ]] ||
    die 'Missing repository requirements or runtime launcher.'
command -v uv >/dev/null || die 'uv is required; use the Codex Cloud Python image.'
python_bin="$(command -v "${CLAUDE_SEO_PYTHON:-python3}")" || die 'Python is required.'
"$python_bin" -c 'import sys; assert (3,11) <= sys.version_info[:2] <= (3,14), "Python 3.11 through 3.14 is required"'
export CLAUDE_SEO_PYTHON="$python_bin"

# Fixed, dedicated Cloud paths preserve the previous onboarding installation.
# Refuse symlinked state roots rather than following them outside /workspace.
for state_dir in /workspace/.uv-cache /workspace/.claude-seo-dev /workspace/.claude-seo-runtime /workspace/.pip-cache; do
    [[ ! -L "$state_dir" ]] || die "Refusing symlinked state directory: $state_dir"
    [[ ! -e "$state_dir" || -d "$state_dir" ]] || die "Not a directory: $state_dir"
done
export UV_CACHE_DIR=/workspace/.uv-cache
export PIP_CACHE_DIR=/workspace/.pip-cache
export CLAUDE_SEO_DATA_DIR=/workspace/.claude-seo-runtime
export UV_PYTHON_DOWNLOADS=never
export PIP_NO_INPUT=1
dev_python=/workspace/.claude-seo-dev/bin/python
if [[ ! -e /workspace/.claude-seo-dev ]]; then
    uv venv --python "$python_bin" /workspace/.claude-seo-dev
fi
[[ -f /workspace/.claude-seo-dev/pyvenv.cfg && -x "$dev_python" ]] ||
    die 'Existing development directory is not a usable venv; inspect it manually.'
"$dev_python" -c 'import sys; assert sys.prefix != sys.base_prefix; assert (3,11) <= sys.version_info[:2] <= (3,14)'

# uv.lock contains no runtime dependencies; requirements.txt is authoritative.
# Keep its bounds intact; pin only the development tools used here.
uv pip install --python "$dev_python" -r requirements.txt pytest==9.2.0 ruff==0.17.1
uv pip check --python "$dev_python"
if ./scripts/claude-seo setup "${skip_browser[@]}"; then
    ./scripts/claude-seo doctor --json
else
    setup_status=$?
    printf 'Runtime setup failed (exit %s). Check dependency, TLS and network diagnostics.\n' "$setup_status" >&2
    exit "$setup_status"
fi
if (( ${#skip_browser[@]} )); then
    printf '%s\n' 'Core-only setup selected; Chromium readiness is not established.'
fi
