"""A trusted egress socket must never become a trusted audit destination."""
from __future__ import annotations

import base64
import http.server
import io
import json
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest
import requests
from urllib3._collections import HTTPHeaderDict
from urllib3.response import HTTPResponse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import url_safety as safety  # noqa: E402


def addresses(ip, port):
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    sockaddr = (ip, port) if family == socket.AF_INET else (ip, port, 0, 0)
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', sockaddr)]


@pytest.fixture
def egress(monkeypatch):
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.delenv('NO_PROXY', raising=False)
    monkeypatch.delenv('CLAUDE_SEO_LOCAL_TARGETS', raising=False)
    monkeypatch.setattr(safety, '_managed_proxy_manifest', lambda: 'http://egress.test:8080')
    monkeypatch.setattr(safety, '_platform_file_text', lambda path: '172.20.0.2 egress.test\n')
    proxies = {'http': 'http://egress.test:8080', 'https': 'http://egress.test:8080'}
    monkeypatch.setattr(requests.utils, 'getproxies', lambda: dict(proxies))
    hosts = {'egress.test': '172.20.0.2', 'public.test': '93.184.216.34',
             'rebind.test': '10.0.0.2'}

    def resolver(host, port, *args, **kwargs):
        return addresses(hosts.get(host, host), port or 0)

    monkeypatch.setattr(socket, 'getaddrinfo', resolver)
    return proxies, hosts


def response(request, status=200, location=None):
    result = requests.Response()
    result.status_code = status
    result.url = request.url
    result.request = request
    result._content = b'body'
    result._content_consumed = True
    if location:
        result.headers['Location'] = location
    return result


def test_exact_platform_socket_is_pinned_but_not_other_ports(egress):
    host, port, ip = safety._managed_proxy('https://public.test/')
    with safety._pin_dns('public.test', '93.184.216.34', 443,
                         proxy_pins={(host, port): ip}):
        assert socket.getaddrinfo(host, port)[0][4] == ('172.20.0.2', 8080)
        with pytest.raises(socket.gaierror, match='non-public'):
            socket.getaddrinfo(host, 8081)
        with pytest.raises(socket.gaierror, match='non-public'):
            socket.getaddrinfo('10.0.0.99', 8080)


def test_proxy_dns_rebinding_cannot_change_captured_transport(egress):
    host, port, ip = safety._managed_proxy('https://public.test/')
    egress[1][host] = '169.254.169.254'
    with safety._pin_dns('public.test', '93.184.216.34', 443,
                         proxy_pins={(host, port): ip}):
        assert socket.getaddrinfo(host, port)[0][4][0] == '172.20.0.2'


def test_private_proxy_dns_must_match_immutable_platform_hosts(egress):
    egress[1]['egress.test'] = '192.168.1.22'
    with pytest.raises(safety.URLSafetyError, match='static platform address'):
        safety._managed_proxy('https://public.test/')


@pytest.mark.parametrize('proxy', [
    'http://egress.test:8081', 'https://egress.test:8080',
    'http://evil.test:8080', 'http://user:secret@egress.test:8080',
    'http://egress.test:8080/extra',
])
def test_environment_cannot_expand_platform_proxy_trust(egress, proxy):
    assert safety._managed_proxy('https://public.test/', {'https': proxy}) is None


@pytest.mark.parametrize('ip', ['169.254.169.254', '100.100.100.200', 'fe80::1', '::'])
def test_metadata_and_special_proxy_addresses_are_never_trusted(egress, ip):
    egress[1]['egress.test'] = ip
    with pytest.raises(safety.URLSafetyError, match='Unsafe managed proxy'):
        safety._managed_proxy('https://public.test/')


@pytest.mark.parametrize('target', [
    'http://127.0.0.1/', 'http://169.254.169.254/latest/meta-data/',
    'http://egress.test:8080/', 'http://rebind.test/',
    'http://2130706433/', 'http://[::1]/',
])
def test_proxy_trust_does_not_allow_private_audits_or_redirects(egress, monkeypatch, target):
    monkeypatch.setenv('CLAUDE_SEO_LOCAL_TARGETS', '127.0.0.1,egress.test,rebind.test')
    calls = []

    def send(adapter, request, **kwargs):
        calls.append(request.url)
        return response(request, 302, target)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    with pytest.raises(safety.URLSafetyError):
        safety.safe_requests_get('https://public.test/')
    assert calls == ['https://public.test/']


def test_each_session_request_is_checked_and_original_tls_identity_is_preserved(egress, monkeypatch):
    seen = []

    def send(adapter, request, **kwargs):
        assert kwargs['verify']  # inherited CA verification remains enabled
        assert request.url == 'https://public.test/page'
        assert socket.getaddrinfo('public.test', 443)[0][4][0] == '93.184.216.34'
        assert socket.getaddrinfo('egress.test', 8080)[0][4][0] == '172.20.0.2'
        seen.append(request.url)
        return response(request)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    with safety.safe_requests_session('https://public.test/') as session:
        assert session.get('https://public.test/page').status_code == 200
        with pytest.raises(safety.URLSafetyError):
            session.get('http://rebind.test/')
    assert len(seen) == 1


def test_target_dns_rebinding_is_rechecked_before_transport(egress, monkeypatch):
    adapter = safety._ManagedProxyAdapter()
    safety.validate_url_strict('https://public.test/')
    egress[1]['public.test'] = '10.0.0.8'
    request = requests.Request('GET', 'https://public.test/').prepare()
    with pytest.raises(safety.URLSafetyError, match='DNS rebinding'):
        adapter.send(request, proxies=egress[0], verify=True)


def test_tls_verification_cannot_be_disabled_for_managed_requests(egress):
    with pytest.raises(safety.URLSafetyError, match='TLS verification'):
        safety.safe_requests_get('https://public.test/', verify=False)


@pytest.mark.parametrize('problem', ['writable', 'owner', 'self-owned', 'symlink', 'group-write', 'missing', 'invalid'])
def test_manifest_trust_fails_closed(monkeypatch, problem):
    if problem == 'self-owned':
        monkeypatch.setattr(safety.os, 'geteuid', lambda: 0, raising=False)
    def info(path):
        if problem == 'missing':
            raise FileNotFoundError()
        kind = stat.S_IFREG if path.name == 'network-policy.json' else stat.S_IFDIR
        return SimpleNamespace(st_uid=1000 if problem == 'owner' else 0,
                               st_mode=(stat.S_IFLNK | 0o444) if problem == 'symlink'
                               else kind | (0o664 if problem == 'group-write' else 0o444))

    monkeypatch.setattr(Path, 'lstat', info)
    monkeypatch.setattr(safety.os, 'access', lambda *args: problem == 'writable')
    payload = 'not json' if problem == 'invalid' else json.dumps(
        {'version': 1, 'http_proxy': 'http://egress.test:8080'}
    )
    monkeypatch.setattr(Path, 'open', lambda *a, **k: io.StringIO(payload))
    assert safety._managed_proxy_manifest() is None


def test_readonly_platform_manifest_is_recognized(monkeypatch):
    monkeypatch.setattr(Path, 'lstat', lambda path: SimpleNamespace(
        st_uid=65534, st_mode=(stat.S_IFREG if path.name == 'network-policy.json'
                              else stat.S_IFDIR) | 0o444))
    monkeypatch.setattr(safety.os, 'access', lambda *args: False)
    monkeypatch.setattr(Path, 'open', lambda *a, **k: io.StringIO(json.dumps(
        {'version': 1, 'http_proxy': 'http://egress.test:8080'}
    )))
    assert safety._managed_proxy_manifest() == 'http://egress.test:8080'


class Route:
    action = None
    payload = None

    def abort(self):
        self.action = 'abort'

    def continue_(self):
        self.action = 'continue'

    def fulfill(self, **kwargs):
        self.action = 'fulfill'
        self.payload = kwargs


def browser_request(url):
    return SimpleNamespace(url=url, resource_type='document', method='GET',
                           post_data_buffer=None, all_headers=lambda: {})


def test_browser_uses_verified_proxy_transport_not_chromium_direct(egress, monkeypatch):
    calls = []

    def send(adapter, request, **kwargs):
        assert kwargs['verify']
        calls.append(request.url)
        return response(request)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    route = Route()
    safety.make_safe_playwright_route_handler()(route, browser_request('https://public.test/'))
    assert route.action == 'fulfill'
    assert route.payload['body'] == b'body'
    assert calls == ['https://public.test/']


@pytest.mark.parametrize('url', ['http://169.254.169.254/', 'http://rebind.test/', 'http://[::1]/'])
def test_browser_subresources_keep_ssrf_checks(egress, url):
    route = Route()
    safety.make_safe_playwright_route_handler()(route, browser_request(url))
    assert route.action == 'abort'


def test_browser_tls_error_aborts_without_direct_fallback(egress, monkeypatch):
    def send(*args, **kwargs):
        raise requests.exceptions.SSLError('Untrusted certificate')

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    route = Route()
    handler = safety.make_safe_playwright_route_handler()
    handler(route, browser_request('https://public.test/'))
    assert route.action == 'abort'
    assert handler.failures == ['Browser resource TLS verification failed']


def test_private_proxy_without_platform_declaration_is_still_refused(egress, monkeypatch):
    monkeypatch.setattr(safety, '_managed_proxy_manifest', lambda: None)
    with pytest.raises(safety.URLSafetyError, match='Refusing configured HTTP proxy'):
        safety.safe_requests_get('https://public.test/')


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_browser_redirect_is_blocked_before_unguarded_native_follow(egress, monkeypatch, status):
    calls = []

    def send(adapter, request, **kwargs):
        calls.append(request.url)
        return response(request, status, 'http://169.254.169.254/latest')

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler()
    first = Route()
    handler(first, browser_request('https://public.test/'))
    assert first.action == 'abort'
    assert handler.failures and 'redirect blocked' in handler.failures[0]
    assert calls == ['https://public.test/']


def test_browser_decoded_body_and_cookies_are_preserved(egress, monkeypatch):
    def send(adapter, request, **kwargs):
        result = response(request)
        result.headers.update({'Content-Encoding': 'gzip', 'Content-Length': '999',
                               'set-cookie': 'session=test; Secure; HttpOnly'})
        return result

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    route = Route()
    safety.make_safe_playwright_route_handler()(route, browser_request('https://public.test/'))
    assert route.action == 'fulfill'
    assert route.payload['body'] == b'body'
    headers = route.payload['headers']
    assert not any(key.lower() in ('content-length', 'content-encoding') for key in headers)
    assert headers['Set-Cookie'] == 'session=test; Secure; HttpOnly'


def test_browser_oversized_resource_aborts_without_fallback(egress, monkeypatch):
    monkeypatch.setattr(safety, 'MAX_PAGE_BYTES', 3)
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send',
                        lambda adapter, request, **kwargs: response(request))
    route = Route()
    safety.make_safe_playwright_route_handler()(route, browser_request('https://public.test/'))
    assert route.action == 'abort'


@pytest.mark.parametrize('status', [301, 302, 307, 308])
@pytest.mark.parametrize('location', [
    'http://127.0.0.1/', 'http://169.254.169.254/latest',
    '//metadata.google.internal/', 'http://rebind.test/', 'http://[::1]/',
])
def test_all_redirect_statuses_revalidate_destination(egress, monkeypatch, status, location):
    calls = []

    def send(adapter, request, **kwargs):
        calls.append(request.url)
        return response(request, status, location)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    with pytest.raises(safety.URLSafetyError):
        safety.safe_requests_get('https://public.test/')
    assert calls == ['https://public.test/']


@pytest.mark.parametrize('status', [301, 302, 307, 308])
def test_public_redirect_rechecks_dns_and_preserves_tls(egress, monkeypatch, status):
    egress[1]['next.test'] = '93.184.216.35'
    calls = []

    def send(adapter, request, **kwargs):
        calls.append(request.url)
        assert kwargs['verify']
        host = urlparse(request.url).hostname
        if host == 'next.test':
            assert 'Authorization' not in request.headers
        assert socket.getaddrinfo(host, 443)[0][4][0] == egress[1][host]
        return response(request, status, 'https://next.test/end') if len(calls) == 1 else response(request)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    result = safety.safe_requests_get('https://public.test/', headers={'Authorization': 'Bearer TEST'})
    assert result.status_code == 200
    assert calls == ['https://public.test/', 'https://next.test/end']


@pytest.mark.parametrize('api', ['get', 'head', 'session'])
def test_tls_cannot_be_disabled_without_a_managed_proxy(egress, monkeypatch, api):
    monkeypatch.setattr(requests.utils, 'getproxies', lambda: {})
    monkeypatch.setattr(requests, 'get', lambda *a, **k: SimpleNamespace(status_code=200))
    monkeypatch.setattr(requests, 'head', lambda *a, **k: SimpleNamespace(status_code=200))
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send',
                        lambda adapter, request, **kwargs: response(request))
    with pytest.raises(safety.URLSafetyError, match='TLS verification'):
        if api == 'session':
            with safety.safe_requests_session('https://public.test/') as session:
                session.get('https://public.test/', verify=False)
        else:
            getattr(safety, 'safe_requests_' + api)('https://public.test/', verify=False)


def test_guarded_browser_context_cannot_ignore_tls_errors():
    context = SimpleNamespace(route=lambda *a: None, route_web_socket=lambda *a: None)
    browser = SimpleNamespace(new_context=lambda **kwargs: context)
    with pytest.raises(safety.URLSafetyError, match='TLS verification'):
        safety.new_guarded_context(browser, lambda *a: None, ignore_https_errors=True)


@pytest.fixture
def chromium():
    playwright = pytest.importorskip('playwright.sync_api')
    with playwright.sync_playwright() as driver:
        if not Path(driver.chromium.executable_path).is_file():
            pytest.skip('Install Chromium and set PLAYWRIGHT_BROWSERS_PATH for browser integration tests')
        browser = driver.chromium.launch(headless=True)
        try:
            yield browser
        finally:
            browser.close()


@pytest.mark.parametrize('transport', ['managed', 'direct'])
def test_real_browser_cookies_javascript_and_dynamic_resources(egress, monkeypatch, chromium, transport):
    if transport == 'direct':
        monkeypatch.setattr(requests.utils, 'getproxies', lambda: {})
    seen = []
    tiny_png = base64.b64decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l2sAAAAASUVORK5CYII='
    )

    def send(adapter, request, **kwargs):
        assert kwargs['verify']
        path = urlparse(request.url).path
        seen.append((path, request.headers.get('Cookie', '')))
        result = response(request)
        result.headers['Content-Type'] = 'text/html; charset=utf-8'
        if path == '/start':
            result.raw = HTTPResponse(body=io.BytesIO(), headers=HTTPHeaderDict([
                ('Set-Cookie', 'secret=fixture; Path=/; Secure; HttpOnly; SameSite=Lax'),
                ('Set-Cookie', 'visible=fixture; Path=/; Secure; SameSite=Lax'),
            ]))
            result._content = (
                b'<html><head><title>Initial</title><script src="/dynamic.js"></script></head>'
                b'<body><img src="/pixel.png"><div id="result">pending</div></body></html>'
            )
        elif path == '/dynamic.js':
            result.headers['Content-Type'] = 'application/javascript'
            result._content = (
                b'window.addEventListener("DOMContentLoaded",async()=>{'
                b'const data=await (await fetch("/api")).json();'
                b'document.querySelector("#result").textContent=data.ok?"ready":"bad";'
                b'document.title="Dynamic ready";});'
            )
        elif path == '/api':
            result.headers['Content-Type'] = 'application/json'
            result._content = b'{"ok":true}'
        elif path == '/pixel.png':
            result.headers['Content-Type'] = 'image/png'
            result._content = tiny_png
        else:
            result.status_code = 404
        return result

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler()
    context = safety.new_guarded_context(chromium, handler)
    try:
        page = context.new_page()
        result = page.goto('https://public.test/start', wait_until='networkidle')
        page.wait_for_function('document.title === "Dynamic ready"')
        assert result.status == 200
        assert page.url == 'https://public.test/start'
        assert page.locator('#result').inner_text() == 'ready'
        cookies = {cookie['name']: cookie for cookie in context.cookies()}
        assert cookies['secret']['httpOnly'] and cookies['secret']['secure']
        assert cookies['visible']['secure']
        assert 'secret=' not in page.evaluate('document.cookie')
        assert 'visible=fixture' in page.evaluate('document.cookie')
        assert page.locator('img').evaluate('(img) => img.complete && img.naturalWidth === 1')
        assert {'/start', '/dynamic.js', '/api', '/pixel.png'} <= {p for p, _ in seen}
        assert all('secret=fixture' in cookie and 'visible=fixture' in cookie
                   for path, cookie in seen if path == '/api')
    finally:
        context.close()


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
@pytest.mark.parametrize('location', ['http://169.254.169.254/latest'])
def test_real_browser_redirect_aborts_before_any_native_target_connection(
    egress, monkeypatch, chromium, status, location,
):
    from playwright.sync_api import Error
    seen = []

    def send(adapter, request, **kwargs):
        seen.append(request.url)
        return response(request, status, location)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler()
    context = safety.new_guarded_context(chromium, handler)
    try:
        page = context.new_page()
        with pytest.raises(Error, match='ERR_BLOCKED_BY_CLIENT'):
            page.goto('https://public.test/start')
        assert seen == ['https://public.test/start']
        assert handler.failures and 'blocked by safety policy' in handler.failures[0]
    finally:
        context.close()


@pytest.mark.parametrize('value', [0, False, '', 'http://egress.test:0', 'http://egress.test:65536'])
def test_invalid_proxy_endpoints_cannot_gain_transport_trust(egress, value):
    with pytest.raises((safety.URLSafetyError, ValueError)):
        safety._proxy_endpoint(value)


@pytest.mark.parametrize('status', [301, 302, 307, 308])
def test_http_redirect_method_and_body_semantics(egress, monkeypatch, status):
    seen = []

    def send(adapter, request, **kwargs):
        seen.append((request.method, request.body))
        return response(request, status, '/end') if len(seen) == 1 else response(request)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    with safety.safe_requests_session('https://public.test/') as session:
        result = session.post('https://public.test/', data=b'fixture-only')
    assert result.status_code == 200
    expected = ('POST', b'fixture-only') if status in (307, 308) else ('GET', None)
    assert seen == [('POST', b'fixture-only'), expected]


def test_actual_untrusted_certificate_is_rejected(monkeypatch, tmp_path):
    executable = shutil.which('openssl')
    if not executable:
        pytest.skip('openssl is required to generate an ephemeral TLS test certificate')
    certificate, key = tmp_path / 'certificate.pem', tmp_path / 'key.pem'
    subprocess.run([
        executable, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', str(key), '-out', str(certificate), '-days', '1',
        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ], check=True, capture_output=True)
    calls = []

    class Page(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Page)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    # Test-only, exact dev-server opt-in; no production proxy variable changes.
    monkeypatch.setenv('CLAUDE_SEO_LOCAL_TARGETS', f'127.0.0.1:{server.server_port}')
    monkeypatch.setattr(requests.utils, 'getproxies', lambda: {})
    try:
        with pytest.raises(requests.exceptions.SSLError):
            safety.safe_requests_get(f'https://127.0.0.1:{server.server_port}/', timeout=3)
        assert calls == []  # Certificate verification failed before HTTP.
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


@pytest.mark.parametrize('status', [301, 302, 307, 308])
@pytest.mark.parametrize('api', ['get', 'head', 'session'])
def test_public_proxy_redirects_cannot_bypass_target_validation(egress, monkeypatch, status, api):
    monkeypatch.setattr(safety, '_managed_proxy_manifest', lambda: None)
    egress[1]['egress.test'] = '8.8.4.4'
    seen = []

    def send(adapter, request, **kwargs):
        seen.append(request.url)
        return response(request, status, 'http://169.254.169.254/latest')

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    with pytest.raises(safety.URLSafetyError):
        if api == 'session':
            with safety.safe_requests_session('https://public.test/') as session:
                session.get('https://public.test/')
        else:
            getattr(safety, 'safe_requests_' + api)('https://public.test/', allow_redirects=True)
    assert seen == ['https://public.test/']


@pytest.mark.parametrize('status', [301, 302, 307, 308])
def test_public_proxy_public_redirects_still_work(egress, monkeypatch, status):
    monkeypatch.setattr(safety, '_managed_proxy_manifest', lambda: None)
    egress[1]['egress.test'] = '8.8.4.4'
    egress[1]['next.test'] = '93.184.216.35'
    seen = []

    def send(adapter, request, **kwargs):
        seen.append(request.url)
        return response(request, status, 'https://next.test/end') if len(seen) == 1 else response(request)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    assert safety.safe_requests_get('https://public.test/').status_code == 200
    assert seen == ['https://public.test/', 'https://next.test/end']


@pytest.mark.parametrize('status', [301, 302, 307, 308])
def test_custom_session_hooks_cannot_remove_redirect_guard(egress, monkeypatch, status):
    monkeypatch.setattr(safety, '_managed_proxy_manifest', lambda: None)
    egress[1]['egress.test'] = '8.8.4.4'
    seen = []

    def send(adapter, request, **kwargs):
        seen.append(request.url)
        return response(request, status, 'http://169.254.169.254/latest')

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    with safety.safe_requests_session('https://public.test/') as session:
        with pytest.raises(safety.URLSafetyError):
            session.get('https://public.test/', hooks={'response': lambda r, *a, **k: r})
    assert seen == ['https://public.test/']
