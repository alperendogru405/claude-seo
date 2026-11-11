# Codex Cloud development workflow

Use the existing checkout below `/workspace`; do not create a Git worktree unless explicitly requested. These two files belong at its root. No persistent application server is required.

## Install

From the repository root, configure the Codex Cloud setup command as:

```bash
bash ./cloud-seo-install.sh
```

The script locates the checkout from its own location, so calling it by absolute path from another directory also works. It requires Bash, preinstalled `uv`, and Python 3.11–3.14 (`CLAUDE_SEO_PYTHON` may select an executable). It never downloads a Python toolchain. A shared Cloud instance should use one checkout with these state directories; do not run concurrent installations.

| Path | Purpose |
| --- | --- |
| `/workspace/.claude-seo-dev` | Development venv; pytest 9.2.0 and Ruff 0.17.1 |
| `/workspace/.claude-seo-runtime` | Managed runtime, state and Playwright browsers |
| `/workspace/.uv-cache` | uv package cache |
| `/workspace/.pip-cache` | pip cache used by managed setup |

Existing development venvs are reused. Invalid directories cause a failure instead of being deleted. The repository's managed `setup` rebuilds its own venv using staging and rollback; it may replace previous runtime state and browser readiness. The fixed paths are dedicated generated state, outside the checkout, and must not contain user files. Root symlinks are rejected. Reruns refresh dependencies within the repository's declared version ranges; this is not a fully locked installation. The current `uv.lock` contains only project metadata, so `uv sync --frozen` would omit runtime dependencies.

Both environments install the unchanged `requirements.txt`. No global packages, sudo, API credentials, or source edits are needed. pip and uv install packages from the configured trusted indexes with inherited TLS and proxy settings; package installation can execute dependency build code. Keep the Cloud image, repository and configured indexes trusted. Do not disable TLS or URL safety, overwrite proxy settings, or work around network policy.

Allow `pypi.org` and `files.pythonhosted.org` (the package-manager preset normally covers them). Chromium needs `cdn.playwright.dev` plus its download redirect host `storage.googleapis.com` (observed for Chromium 158.0.8127.18). Add missing hosts in environment settings while preserving existing rules; future Playwright versions may use other hosts. Browser system libraries must also be present in the Cloud image; if launch reports missing libraries, install the exact packages through the supported Cloud package installer, then retry. The script does not change system packages or the network policy.

For explicitly limited work, `bash ./cloud-seo-install.sh --skip-browser` installs the core runtime. This does not establish rendered-page readiness. Default setup preserves nonzero failure codes, including exit 10 when Chromium installation fails.

## Start and validate

In the checkout root, export these variables in each new shell:

```bash
export CLAUDE_SEO_DATA_DIR=/workspace/.claude-seo-runtime
export UV_CACHE_DIR=/workspace/.uv-cache
export PIP_CACHE_DIR=/workspace/.pip-cache
./scripts/claude-seo doctor --json
./scripts/claude-seo run seo_updates.py --limit 1 --json
/workspace/.claude-seo-dev/bin/python -m pytest tests/ -q
/workspace/.claude-seo-dev/bin/ruff check .
```

If installation used `CLAUDE_SEO_PYTHON`, export the same executable path before running the launcher. Doctor must report `ready: true`; rendered-page work additionally requires `browser_ready: true` and a successful actual browser operation. A successful download or doctor response alone does not verify browser launch or external website access. The Google update smoke command reads bundled data and should return `count: 1`.

Run bundled SEO tools through `./scripts/claude-seo run <script.py> <args>`, never through the managed venv interpreter directly. The separate development interpreter above is for tests. Paid API extensions are optional; add credentials securely through environment settings only when needed. Never commit credentials, generated venvs, caches, logs, or audit outputs.

Some tests require public DNS or live HTTP even without the optional network-test flag. The repository's URL-safety code can reject the managed private proxy. Diagnose these failures without removing the proxy or weakening SSRF checks. Some backlink caches default to a home-directory path that may be read-only in the agent sandbox; use supported local configuration or report the specific permission requirement. Keep failed, skipped and passed test results distinct.

## Environment settings

GitHub stores these helper files; that does not automatically save Cloud configuration or publish an environment. Set the setup command to invoke the checked-out script and use this document as startup guidance in environment settings. Processes do not survive snapshots; a new task must recheck readiness. Historical test results are not a guarantee for a new machine or newly resolved dependencies.

Review on 2026-11-11 (latest retest): the unmodified installation script completed with exit 0. Doctor reported `ready: true` and `browser_ready: true`. Playwright Chromium 158.0.8127.18 launched and executed an in-memory JavaScript DOM mutation. DNS and verified HTTPS worked for the download hosts, example.com and www.python.org. The download URL returned HTTP 307 then HTTP 200; the earlier storage.googleapis.com policy block was absent in this retest. Ruff and portability checks passed (35 skill files, no warnings). All 73 development packages were compatible. HTML parsing, robots allow/disallow and sitemap declarations, sitemap XML classification, canonical, description, robots and Open Graph checks passed.

The full existing test suite completed with **2352 passed, 3 failed, 3 skipped**. Failures: `test_render_page_never_mode_against_example_com`, `test_safe_requests_head_uses_strict_validation_and_dns_pin`, and `test_proxy_hosts_reads_environment_and_honours_no_proxy`. The SEO raw fetch rejects the managed proxy because it resolves to private IP 172.31.9.237. A local guarded rendered-page navigation also failed with `Page.goto: net::ERR_FAILED`; standalone Chromium JavaScript execution passed. These results do not establish end-to-end crawl readiness. Keep the managed proxy and SSRF safeguards intact; resolve their compatibility in a separate authorized source-code task. Additional domain permission alone does not fix the proxy rejection.

Published-snapshot verification on 2026-11-11: both helper files survived restoration as untracked repository-root files. Running the installation script from `/tmp` completed with exit 0; doctor reported core and browser ready. Chromium 158.0.8127.18 launched and executed JavaScript. Bash syntax, Ruff, portability lint and the bundled Google-update smoke command passed; the existing runtime, installer and Python-range test subset passed all 33 tests. The full suite and external-site crawling were not rerun during this commit preparation.
