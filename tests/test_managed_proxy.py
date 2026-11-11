"""A trusted egress socket must never become a trusted audit destination."""
from __future__ import annotations

import io
import json
import socket
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

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
    safety.make_safe_playwright_route_handler()(route, browser_request('https://public.test/'))
    assert route.action == 'abort'


def test_private_proxy_without_platform_declaration_is_still_refused(egress, monkeypatch):
    monkeypatch.setattr(safety, '_managed_proxy_manifest', lambda: None)
    with pytest.raises(safety.URLSafetyError, match='Refusing configured HTTP proxy'):
        safety.safe_requests_get('https://public.test/')


def test_browser_redirect_is_not_followed_before_next_guard(egress, monkeypatch):
    calls = []

    def send(adapter, request, **kwargs):
        calls.append(request.url)
        return response(request, 302, 'http://169.254.169.254/latest')

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler()
    first, redirected = Route(), Route()
    handler(first, browser_request('https://public.test/'))
    assert first.action == 'fulfill' and first.payload['status'] == 302
    handler(redirected, browser_request(first.payload['headers']['Location']))
    assert redirected.action == 'abort'
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
