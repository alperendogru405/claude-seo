"""Real Chromium, native redirects; only the upstream HTTP fixture is mocked."""
from __future__ import annotations

import sys
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import url_safety as safety  # noqa: E402
from test_managed_proxy import egress as egress
from test_managed_proxy import response
from urllib3._collections import HTTPHeaderDict
from urllib3.response import HTTPResponse


@pytest.fixture(scope='module')
def playwright_driver():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as driver:
        if not Path(driver.chromium.executable_path).is_file():
            pytest.skip('Install Chromium and set PLAYWRIGHT_BROWSERS_PATH')
        yield driver


@pytest.fixture(scope='module')
def chromium(playwright_driver):
    browser = playwright_driver.chromium.launch(headless=True)
    yield browser
    browser.close()


def html_response(request, body=b'<title>Final JS</title>', status=200, cookies=()):
    result = response(request, status)
    result._content = body
    result.headers['Content-Type'] = 'text/html; charset=utf-8'
    if cookies:
        result.raw = HTTPResponse(headers=HTTPHeaderDict([('Set-Cookie', c) for c in cookies]))
    return result


def request_chain(result):
    chain, request = [], result.request
    while request:
        chain.append((request.url, request.method, request.response().status))
        request = request.redirected_from
    return list(reversed(chain))


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
@pytest.mark.parametrize('transition', ['same-origin', 'cross-domain', 'http-to-https'])
def test_native_redirect_preserves_url_status_origin_cookies_and_javascript(
    egress, monkeypatch, chromium, status, transition,
):
    egress[1]['other.test'] = '93.184.216.35'
    start = ('http' if transition == 'http-to-https' else 'https') + '://public.test/start'
    target = 'https://' + ('other.test' if transition == 'cross-domain' else 'public.test') + '/final'
    seen = []

    def send(adapter, request, **kwargs):
        assert kwargs['verify']
        seen.append((request.url, dict(request.headers)))
        if request.url == start:
            result = html_response(request, status=status, cookies=(
                'hop=fixture; Path=/; Secure; HttpOnly; SameSite=Lax',
            ))
            result.headers['Location'] = target
            return result
        assert request.url == target
        return html_response(request, b'<title>Before</title><script>'
                             b'window.seenOrigin=location.origin;document.title="Native JS";</script>',
                             status=201)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler()
    context = safety.new_guarded_context(chromium, handler, extra_http_headers={
        'Authorization': 'Bearer fixture',
    })
    context.add_cookies([
        {'name': 'source', 'value': 'fixture', 'url': start, 'secure': start.startswith('https')},
        {'name': 'target', 'value': 'fixture', 'url': target, 'secure': True, 'httpOnly': True},
    ])
    try:
        page = context.new_page()
        result = page.goto(start, wait_until='networkidle')
        assert page.url == target
        assert result.status == 201  # Not an invented 200.
        assert page.title() == 'Native JS'
        assert page.evaluate('window.seenOrigin') == 'https://' + urlparse(target).hostname
        assert request_chain(result) == [(start, 'GET', status), (target, 'GET', 201)]
        assert [url for url, _ in seen] == [start, target]
        final_headers = requests.structures.CaseInsensitiveDict(seen[-1][1])
        final_cookies = final_headers.get('Cookie', '')
        assert 'target=fixture' in final_cookies
        if transition == 'cross-domain':
            assert 'Authorization' not in final_headers
            assert 'source=fixture' not in final_cookies and 'hop=fixture' not in final_cookies
        elif transition == 'http-to-https':
            assert 'Authorization' not in final_headers  # Scheme changes origin.
            initial_headers = requests.structures.CaseInsensitiveDict(seen[0][1])
            assert 'target=fixture' not in initial_headers.get('Cookie', '')
        else:
            assert final_headers['Authorization'] == 'Bearer fixture'
            assert 'hop=fixture' in final_cookies
        assert not handler.failures
    finally:
        context.close()


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
@pytest.mark.parametrize('target', [
    'http://127.0.0.1/private', 'http://10.0.0.7/private',
    'http://169.254.169.254/latest', 'http://metadata.google.internal/',
    'http://rebind.test/', 'http://[::1]/', 'http://[fd00::1]/',
    'http://2130706433/',
])
def test_native_redirect_private_targets_never_reach_upstream(
    egress, monkeypatch, chromium, status, target,
):
    from playwright.sync_api import Error
    seen = []

    def send(adapter, request, **kwargs):
        seen.append(request.url)
        return response(request, status, target)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler()
    context = safety.new_guarded_context(chromium, handler)
    try:
        page = context.new_page()
        with pytest.raises(Error, match='ERR_'):
            page.goto('https://public.test/start')
        assert seen == ['https://public.test/start']
    finally:
        context.close()


@pytest.mark.parametrize('limit', [0, 1, 3])
def test_native_redirect_loop_and_limit_are_bounded_before_request(
    egress, monkeypatch, chromium, limit,
):
    from playwright.sync_api import Error
    seen = []

    def send(adapter, request, **kwargs):
        seen.append(request.url)
        return response(request, 302, '/loop')

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler(max_redirects=limit)
    context = safety.new_guarded_context(chromium, handler)
    try:
        page = context.new_page()
        with pytest.raises(Error, match='ERR_'):
            page.goto('https://public.test/loop')
        assert len(seen) == limit + 1
        assert any('maximum redirect count' in item for item in handler.failures)
    finally:
        context.close()


def test_same_url_cookie_redirect_is_not_mistaken_for_a_loop(egress, monkeypatch, chromium):
    seen = []

    def send(adapter, request, **kwargs):
        seen.append(request.url)
        if 'unlocked=fixture' not in request.headers.get('Cookie', ''):
            result = html_response(request, status=302, cookies=(
                'unlocked=fixture; Secure; HttpOnly; Path=/',
            ))
            result.headers['Location'] = request.url
            return result
        return html_response(request)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler(max_redirects=3)
    context = safety.new_guarded_context(chromium, handler)
    try:
        page = context.new_page()
        result = page.goto('https://public.test/self')
        assert result.status == 200 and len(seen) == 2
        assert [status for _, _, status in request_chain(result)] == [302, 200]
        assert not handler.failures
    finally:
        context.close()


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
@pytest.mark.parametrize('binary', [False, True])
def test_native_post_redirect_method_body_and_cross_origin_authorization(
    egress, monkeypatch, chromium, status, binary,
):
    egress[1]['other.test'] = '93.184.216.35'
    seen = []

    def send(adapter, request, **kwargs):
        seen.append((request.url, request.method, request.body, dict(request.headers)))
        path = urlparse(request.url).path
        if path == '/page':
            return html_response(request)
        if path == '/start':
            result = response(request, status, 'https://other.test/final')
        else:
            result = response(request)
            result._content = b'completed'
        result.headers['Access-Control-Allow-Origin'] = 'https://public.test'
        result.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        result.headers['Access-Control-Allow-Headers'] = 'authorization,content-type'
        result.headers['Content-Type'] = 'text/plain'
        return result

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler()
    context = safety.new_guarded_context(chromium, handler)
    try:
        page = context.new_page()
        page.goto('https://public.test/page')
        result = page.evaluate("""async binary => {
            const body=binary?new Uint8Array([0,255,192,128,13,10]):'fixture-body';
            const type=binary?'application/octet-stream':'text/plain';
            const r = await fetch('/start', {method:'POST', body,
                headers: {Authorization:'Bearer fixture', 'Content-Type':type}});
            return {url:r.url, status:r.status, body:await r.text()};
        }""", binary)
        assert result == {'url': 'https://other.test/final', 'status': 200, 'body': 'completed'}
        final = next(row for row in seen if row[0] == 'https://other.test/final' and row[1] != 'OPTIONS')
        body = bytes([0, 255, 192, 128, 13, 10]) if binary else b'fixture-body'
        assert final[1:3] == (('POST', body) if status in (307, 308) else ('GET', None))
        assert 'Authorization' not in requests.structures.CaseInsensitiveDict(final[3])
        assert not handler.failures
    finally:
        context.close()


@pytest.mark.parametrize('kind', ['iframe', 'popup', 'worker'])
@pytest.mark.parametrize('private', [False, True])
def test_child_targets_are_guarded_before_native_redirects(
    egress, monkeypatch, chromium, kind, private,
):
    egress[1]['other.test'] = '93.184.216.35'
    egress[1]['third.test'] = '93.184.216.36'
    target = 'http://169.254.169.254/latest' if private else 'https://third.test/final'
    seen = []

    def send(adapter, request, **kwargs):
        seen.append(request.url)
        path = urlparse(request.url).path
        if path == '/start':
            result = response(request, 307, target)
        elif path == '/worker.js':
            result = html_response(request, b'fetch("https://other.test/start")'
                                   b'.then(r=>r.text()).then(t=>postMessage(t))'
                                   b'.catch(()=>postMessage("blocked"));')
            result.headers['Content-Type'] = 'application/javascript'
        elif path == '/final':
            result = html_response(request, b'<title>Child final</title>')
        else:
            result = html_response(request)
        result.headers['Access-Control-Allow-Origin'] = '*'
        return result

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler()
    context = safety.new_guarded_context(chromium, handler)
    try:
        page = context.new_page()
        page.goto('https://public.test/parent')
        if kind == 'iframe':
            create = """() => {
                const frame=document.createElement('iframe');
                frame.src='https://other.test/start';document.body.append(frame);
            }"""
            if private:
                with context.expect_event('requestfailed', predicate=lambda req: req.url == target):
                    page.evaluate(create)
                assert target not in seen
            else:
                with page.expect_event('framenavigated', predicate=lambda frame: frame.url == target):
                    page.evaluate(create)
                frame = page.frame(url=target)
                assert frame is not None
                assert frame.title() == 'Child final'
        elif kind == 'popup':
            if private:
                with context.expect_event('requestfailed', predicate=lambda req: req.url == target):
                    with page.expect_popup() as pending:
                        page.evaluate("window.open('https://other.test/start')")
                popup = pending.value
                assert target not in seen
            else:
                with page.expect_popup() as pending:
                    page.evaluate("window.open('https://other.test/start')")
                popup = pending.value
                try:
                    popup.wait_for_url(target, wait_until='domcontentloaded')
                except Exception as exc:
                    raise AssertionError(f'Popup failed: {handler.failures}') from exc
                assert popup.url == target and popup.title() == 'Child final'
        else:
            value = page.evaluate("""() => new Promise(resolve=>{
                const worker=new Worker('/worker.js');
                worker.onmessage=e=>{worker.terminate();resolve(e.data)};
                worker.onerror=()=>resolve('worker error');
            })""")
            assert value == ('blocked' if private else '<title>Child final</title>')
        assert 'https://other.test/start' in seen
        assert (target in seen) is not private
        assert page.title() == 'Final JS'
        if not private:
            assert not handler.failures
    finally:
        context.close()


def test_guard_does_not_pause_or_modify_unrelated_contexts(egress, monkeypatch, chromium):
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send',
                        lambda adapter, request, **kwargs: html_response(request))
    handler = safety.make_safe_playwright_route_handler()
    guarded = safety.new_guarded_context(chromium, handler)
    other = chromium.new_context()
    other.route('**/*', lambda route: route.fulfill(status=200, body='<title>Unrelated</title>'))
    try:
        page = other.new_page()
        assert page.goto('https://unrelated.test/', timeout=5000).status == 200
        assert page.title() == 'Unrelated'
        assert not handler.failures
    finally:
        other.close()
        guarded.close()


def test_redirect_dns_rebinding_before_transport_is_blocked(egress, monkeypatch, chromium):
    original = safety.socket.getaddrinfo
    counts = [0]

    def resolve(host, port, *args, **kwargs):
        if host == 'next.test':
            counts[0] += 1
            ip = '93.184.216.35' if counts[0] == 1 else '10.0.0.6'
            return [(safety.socket.AF_INET, safety.socket.SOCK_STREAM, 6, '', (ip, port or 0))]
        return original(host, port, *args, **kwargs)

    monkeypatch.setattr(safety.socket, 'getaddrinfo', resolve)
    seen = []

    def send(adapter, request, **kwargs):
        seen.append(request.url)
        return response(request, 302, 'https://next.test/final')

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler()
    context = safety.new_guarded_context(chromium, handler)
    try:
        from playwright.sync_api import Error
        with pytest.raises(Error, match='ERR_'):
            context.new_page().goto('https://public.test/start')
        assert counts[0] >= 2
        assert seen == ['https://public.test/start']
    finally:
        context.close()


def test_cancelled_resource_does_not_close_the_page(egress, monkeypatch, chromium):
    import time

    def send(adapter, request, **kwargs):
        if urlparse(request.url).path == '/cancel':
            time.sleep(0.1)  # Let Chromium cancel while the upstream fixture responds.
        return html_response(request)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler()
    context = safety.new_guarded_context(chromium, handler)
    try:
        page = context.new_page()
        page.goto('https://public.test/parent')
        result = page.evaluate("""async () => {
            const controller=new AbortController();
            const result=fetch('/cancel', {signal:controller.signal}).catch(()=>null);
            setTimeout(()=>controller.abort(),10);
            await result;return 'finished';
        }""")
        page.wait_for_timeout(50)
        assert result == 'finished'
        assert page.title() == 'Final JS'
        assert not handler.failures
    finally:
        context.close()


@pytest.mark.parametrize('private', [False, True])
def test_shared_worker_loads_are_verified_or_denied_without_native_fallback(
    egress, monkeypatch, chromium, private,
):
    egress[1]['other.test'] = '93.184.216.35'
    seen = []
    target = 'http://169.254.169.254/latest' if private else 'https://other.test/final'

    def send(adapter, request, **kwargs):
        seen.append(request.url)
        path = urlparse(request.url).path
        if path == '/shared.js':
            result = html_response(request, b'onconnect=e=>{const port=e.ports[0];'
                                   b'fetch("https://other.test/start").then(r=>r.text())'
                                   b'.then(t=>port.postMessage(t)).catch(()=>port.postMessage("blocked"));};')
            result.headers['Content-Type'] = 'application/javascript'
        elif path == '/start':
            result = response(request, 302, target)
        elif path == '/final':
            result = html_response(request, b'<title>Shared final</title>')
        else:
            result = html_response(request)
        result.headers['Access-Control-Allow-Origin'] = '*'
        return result

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler()
    context = safety.new_guarded_context(chromium, handler)
    try:
        page = context.new_page()
        page.goto('https://public.test/parent')
        value = page.evaluate("""() => new Promise(resolve=>{
            const w=new SharedWorker('/shared.js');w.port.start();
            w.port.onmessage=e=>{w.port.close();resolve(e.data)};
            w.onerror=()=>resolve('worker error');
            setTimeout(()=>resolve('timeout'),1500);
        })""")
        if private:
            assert value == 'blocked'
            assert target not in seen
        elif value == 'blocked':
            # Chromium may not expose this background loader to a frame's
            # Fetch agent. This tests fail-closed isolation, not full support.
            assert target not in seen
        else:
            assert value == '<title>Shared final</title>'
            assert 'https://other.test/start' in seen and target in seen
        assert not any('169.254.' in url for url in seen)
        assert page.title() == 'Final JS'
    finally:
        context.close()


def test_worker_native_websocket_cannot_reach_loopback(egress, monkeypatch, chromium):
    import socket
    sentinel = socket.socket()
    sentinel.bind(('127.0.0.1', 0))
    sentinel.listen()
    sentinel.settimeout(0.1)
    port = sentinel.getsockname()[1]

    def send(adapter, request, **kwargs):
        if urlparse(request.url).path == '/wsworker.js':
            script = (
                f'const ws=new WebSocket("ws://127.0.0.1:{port}/");'
                'ws.onerror=()=>postMessage("blocked");'
                'ws.onopen=()=>postMessage("opened");'
            ).encode()
            result = html_response(request, script)
            result.headers['Content-Type'] = 'application/javascript'
            return result
        return html_response(request)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler()
    context = safety.new_guarded_context(chromium, handler)
    try:
        page = context.new_page()
        page.goto('https://public.test/parent')
        value = page.evaluate("""() => new Promise(resolve=>{
            const worker=new Worker('/wsworker.js');
            worker.onmessage=e=>{worker.terminate();resolve(e.data)};
            worker.onerror=()=>resolve('worker error');
            setTimeout(()=>resolve('timeout'),3000);
        })""")
        assert value in ('blocked', 'opened')  # A mock socket may open without a server.
        with pytest.raises(TimeoutError):
            sentinel.accept()  # No private TCP connection, even outside Fetch.
        assert page.title() == 'Final JS'
    finally:
        context.close()
        sentinel.close()


def test_renderer_reports_native_final_response_and_chain(egress, monkeypatch, playwright_driver):
    import render_page

    @contextmanager
    def shared_driver():
        yield playwright_driver

    # Reuse the real module driver; nesting Sync Playwright event loops on
    # one Python thread is unsupported. The renderer still launches and owns
    # a separate, real Chromium instance.
    monkeypatch.setattr(render_page, 'sync_playwright', shared_driver)
    egress[1]['other.test'] = '93.184.216.35'
    start, final = 'https://public.test/start', 'https://other.test/final'

    def send(adapter, request, **kwargs):
        if request.url == start:
            return response(request, 303, final)
        assert request.url == final
        return html_response(request, b'<html><head><title>Before</title></head><body>'
                             b'<script>document.title="Rendered target";'
                             b'document.body.dataset.origin=location.origin;</script></body></html>',
                             status=201)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    result = render_page.render_page(start, mode='always', extract_content=False, timeout_ms=5000)
    assert result['error'] is None
    assert result['url'] == final and result['status_code'] == 201
    assert result['render_engine'] == 'playwright-chromium'
    assert result['redirect_chain'] == [{'url': start, 'status_code': 303}]
    assert '<title>Rendered target</title>' in result['content']
    assert 'data-origin="https://other.test"' in result['content']


@pytest.mark.parametrize('return_to_source', [False, True])
def test_authorization_never_reappears_after_cross_origin_redirect(
    egress, monkeypatch, chromium, return_to_source,
):
    egress[1]['other.test'] = '93.184.216.35'
    urls = ['https://public.test/start', 'https://other.test/middle',
            'https://' + ('public.test' if return_to_source else 'other.test') + '/final']
    seen = []

    def send(adapter, request, **kwargs):
        seen.append((request.url, requests.structures.CaseInsensitiveDict(request.headers)))
        index = urls.index(request.url)
        return (response(request, 302, urls[index + 1]) if index < 2
                else html_response(request))

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    handler = safety.make_safe_playwright_route_handler()
    context = safety.new_guarded_context(chromium, handler, extra_http_headers={
        'Authorization': 'Bearer fixture',
    })
    try:
        result = context.new_page().goto(urls[0])
        assert result.status == 200 and result.url == urls[-1]
        assert [url for url, _ in seen] == urls
        assert seen[0][1]['Authorization'] == 'Bearer fixture'
        assert all('Authorization' not in headers for _, headers in seen[1:])
        assert not handler.failures
    finally:
        context.close()
