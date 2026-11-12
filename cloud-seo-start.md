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

Some tests require public DNS or live HTTP even without the optional network-test flag. Managed Cloud egress is accepted only when the inherited proxy exactly matches the immutable platform manifest and its private address matches the immutable hosts file. No proxy variable is removed or rewritten. Audit URLs, redirect destinations and browser resources must still resolve publicly; local-target opt-ins do not apply through managed egress. Playwright resource responses use the same verified Python transport, preserving the platform CA/proxy configuration. See `SECURITY.md` for trust boundaries and the proxy's responsibility for destination DNS enforcement. If that platform contract is missing, report the mismatch instead of allowing private proxies generally. Some backlink caches default to a home-directory path that may be read-only in the agent sandbox; use supported local configuration or report the specific permission requirement. Keep failed, skipped and passed test results distinct.

## Environment settings

GitHub stores these helper files; that does not automatically save Cloud configuration or publish an environment. Set the setup command to invoke the checked-out script and use this document as startup guidance in environment settings. Processes do not survive snapshots; a new task must recheck readiness. Historical test results are not a guarantee for a new machine or newly resolved dependencies.

Historical review before the managed-proxy fix on 2026-11-11: the unmodified installation script completed with exit 0. Doctor reported `ready: true` and `browser_ready: true`. Playwright Chromium 158.0.8127.18 launched and executed an in-memory JavaScript DOM mutation. DNS and verified HTTPS worked for the download hosts, example.com and www.python.org. The download URL returned HTTP 307 then HTTP 200; the earlier storage.googleapis.com policy block was absent in this retest. Ruff and portability checks passed (35 skill files, no warnings). All 73 development packages were compatible. HTML parsing, robots allow/disallow and sitemap declarations, sitemap XML classification, canonical, description, robots and Open Graph checks passed.

The full existing test suite completed with **2352 passed, 3 failed, 3 skipped**. Failures: `test_render_page_never_mode_against_example_com`, `test_safe_requests_head_uses_strict_validation_and_dns_pin`, and `test_proxy_hosts_reads_environment_and_honours_no_proxy`. The SEO raw fetch rejects the managed proxy because it resolves to private IP 172.31.9.237. A local guarded rendered-page navigation also failed with `Page.goto: net::ERR_FAILED`; standalone Chromium JavaScript execution passed. Those pre-fix results did not establish end-to-end crawl readiness; they motivated the managed-proxy fix documented above. Additional domain permission alone did not resolve that proxy rejection.

Published-snapshot verification on 2026-11-11: both helper files survived restoration as untracked repository-root files. Running the installation script from `/tmp` completed with exit 0; doctor reported core and browser ready. Chromium 158.0.8127.18 launched and executed JavaScript. Bash syntax, Ruff, portability lint and the bundled Google-update smoke command passed; the existing runtime, installer and Python-range test subset passed all 33 tests. The full suite and external-site crawling were not rerun during this commit preparation.

Managed-proxy fix validation on 2026-11-11: doctor reported core/browser ready; Chromium 158.0.8127.18 executed JavaScript. The three original failing tests passed after the fix. The final full suite completed with **2393 passed, 0 failed, 3 skipped**, including 38 managed-proxy security cases. Ruff and portability lint passed. Read-only HTTP and Playwright fetches of `https://example.com/` both returned 200 and title `Example Domain`; description, canonical and meta robots tags were absent. `/robots.txt` returned 404. No proxy/TLS/SSRF protections were disabled. This verifies the example site in this environment, not credentials or access to arbitrary domains. CONNECT destination DNS enforcement remains a responsibility of the trusted platform proxy.

Historical security audit (before native redirect support): PR #2 is not merge-ready for general browser crawling. Safe HTTP requests validate 301/302/307/308 targets through both managed and public proxies; TLS verification opt-outs are rejected, including caller session-hook overrides. Real Chromium fixtures cover JavaScript, multiple Secure/HttpOnly cookies, images and dynamic fetch resources. Browser HTTP redirects are deliberately blocked before any unguarded native follow, because Playwright routes only their first hop. A redirect-aware transport that preserves status, final URL, origin, cookies and resource semantics is required before declaring that feature complete. The remote CONNECT resolver must separately enforce public-only destination policy; local test success does not prove that platform guarantee. The earlier successful example.com scans cover a page without HTTP redirects.

Historical audit results (before native redirect support): the original PR baseline again passed 2393 tests with 3 skipped. The hardened candidate passed 2467 tests with 0 failures and 3 skipped, including 112 proxy/security cases and real Chromium fixtures for cookies, JavaScript, images, dynamic fetches and blocked redirects. The untrusted-certificate test failed the TLS handshake before HTTP, as required. Live example.com HTTP and Playwright scans still returned 200. Successful negative tests prove redirect blocking, not completed browser redirect support; PR #2 remains not merge-ready until that feature and the remote DNS enforcement requirement are resolved.


Native Chromium redirect follow-up (2026-11-12): CDP Fetch now validates every 301/302/303/307/308 hop before the existing verified Python transport sends it. Real 3xx responses are delivered to Chromium: final URL, status, origin, cookies, redirect chain, JavaScript and native method/body changes are preserved. A mandatory deny-only native connection barrier prevents missed loaders from contacting origins; it does not forward traffic or change inherited platform proxy/CA settings. Other engines retain redirect blocking. SharedWorker loads not exposed to verified interception fail closed; complete SharedWorker compatibility is not claimed.

The previous client-side redirect blocker is addressed, but **the remote CONNECT DNS trust boundary remains unresolved without a platform guarantee**: the provider must enforce public-only resolution, reject private/link-local/metadata destinations and prevent rebinding on every connection. Local tests and example.com success cannot prove this. Keep PR #2 draft and do not treat general managed-proxy crawling as unconditionally merge-ready.

Validation on 2026-11-12: full suite **2557 passed, 0 failed, 3 skipped** (only opt-in live GitHub API cases skipped); Ruff passed; portability checked all **35 skills** with zero errors/warnings. Real Chromium fixtures cover all five redirect statuses, cross-domain and HTTP-to-HTTPS transitions, final 201 status/origin/JavaScript, cookies, text/binary POST semantics, redirect limits, private/metadata/rebinding rejection, and Authorization removal throughout the remaining chain. Fixture upstream HTTP responses are controlled; this is not a claim that arbitrary external domains were scanned. The read-only live example.com scan returned 200 without renderer diagnostics.
