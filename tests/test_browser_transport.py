"""Fail-closed protocol startup and cancellation, without network fixtures."""
from __future__ import annotations

import json
import socket
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import browser_transport as transport  # noqa: E402
import url_safety as safety  # noqa: E402


class Root:
    def __init__(self):
        self.commands = []

    def on(self, *args):
        pass

    def send(self, method, params=None):
        self.commands.append((method, params or {}))
        if method == 'Target.attachToTarget':
            return {'sessionId': 'side'}
        return {}

    def detach(self):
        pass


@pytest.fixture
def state():
    seen = []

    def handler(route, request):
        seen.append(request.url)
        route.abort()

    handler.failures = []
    handler.max_redirects = 2
    root = Root()
    browser = SimpleNamespace(new_browser_cdp_session=lambda: root, on=lambda *a: None)
    controller = transport._Transport(browser, 'context', handler)
    return controller, root, seen, handler


def attach(controller):
    controller.attached((), {'sessionId': 'flat', 'waitingForDebugger': True, 'targetInfo': {
        'targetId': 'target', 'type': 'page', 'browserContextId': 'context',
    }})


def complete_last(controller, root, *, error=None):
    message = json.loads(root.commands[-1][1]['message'])
    result = {'id': message['id'], 'error': error} if error else {'id': message['id'], 'result': {}}
    controller.message((), {'sessionId': 'side', 'message': json.dumps(result)})


def methods(root):
    return [json.loads(params['message'])['method'] if method == 'Target.sendMessageToTarget'
            else method for method, params in root.commands]


def paused_event():
    return {'requestId': 'request', 'resourceType': 'Document',
            'request': {'url': 'https://public.test/start', 'method': 'GET', 'headers': {}}}


def test_startup_requests_wait_for_fetch_and_child_guards_before_resume(state):
    controller, root, seen, _handler = state
    attach(controller)
    controller.paused(('side',), paused_event())
    assert seen == [] and len(controller.bindings[('side',)].pending) == 1
    assert 'Runtime.runIfWaitingForDebugger' not in methods(root)
    complete_last(controller, root)  # Fetch.enable ack.
    assert seen == [] and not controller.bindings[('side',)].ready
    assert 'Runtime.runIfWaitingForDebugger' not in methods(root)
    complete_last(controller, root)  # Child-target auto-attach ack.
    assert seen == ['https://public.test/start']
    assert controller.bindings[('side',)].ready
    assert methods(root).index('Target.detachFromTarget') < methods(root).index('Runtime.runIfWaitingForDebugger')
    assert 'Fetch.continueRequest' not in methods(root)


def test_fetch_setup_failure_closes_target_without_resuming_or_fallback(state):
    controller, root, seen, handler = state
    attach(controller)
    complete_last(controller, root, error={'code': -32601, 'message': 'unsupported'})
    assert 'Target.closeTarget' in methods(root)
    assert 'Runtime.runIfWaitingForDebugger' not in methods(root)
    assert 'Fetch.continueRequest' not in methods(root)
    assert seen == [] and handler.failures


def test_untracked_redirect_cannot_reset_limit_or_reach_transport(state):
    controller, root, seen, handler = state
    controller.bindings[('side',)] = transport._Binding('target', 'context', ready=True)
    event = paused_event()
    event['redirectedRequestId'] = 'unknown'
    controller.paused(('side',), event)
    assert seen == [] and handler.failures
    assert methods(root)[-1] == 'Fetch.failRequest'


def test_cancelled_interception_does_not_close_live_target(state):
    controller, root, _seen, handler = state
    controller.bindings[('side',)] = transport._Binding('target', 'context', ready=True)
    controller.send(('side',), 'Fetch.fulfillRequest', {'requestId': 'cancelled'})
    complete_last(controller, root, error={'code': -32000, 'message': 'Invalid InterceptionId.'})
    assert not handler.failures and 'Target.closeTarget' not in methods(root)


def test_child_envelope_error_does_not_close_parent_after_worker_destruction(state):
    controller, root, _seen, handler = state
    controller.bindings[('side',)] = transport._Binding('parent', 'context', ready=True)
    controller.bindings[('side', 'child')] = transport._Binding('worker', 'context', ready=True)
    controller.send(('side', 'child'), 'Fetch.fulfillRequest', {'requestId': 'cancelled'})
    del controller.bindings[('side', 'child')]
    complete_last(controller, root, error={'code': -32000, 'message': 'No session with given id'})
    assert ('side',) in controller.bindings
    assert not handler.failures and 'Target.closeTarget' not in methods(root)


@pytest.mark.parametrize('value', [-1, 21, True, '3', None])
def test_invalid_redirect_limits_are_rejected(value):
    with pytest.raises(ValueError):
        safety.make_safe_playwright_route_handler(max_redirects=value)


def test_context_native_barrier_reserves_a_non_listening_port_and_removes_bypass(monkeypatch):
    callbacks = []
    options = {}

    def closed():
        for callback in callbacks:
            callback()

    context = SimpleNamespace(on=lambda _name, fn: callbacks.append(fn),
                              route_web_socket=lambda *a: None, close=closed)

    def new_context(**kwargs):
        options.update(kwargs)
        return context

    browser = SimpleNamespace(browser_type=SimpleNamespace(name='chromium'), new_context=new_context)
    monkeypatch.setattr(transport, 'install', lambda *a: None)
    result = safety.new_guarded_context(browser, safety.make_safe_playwright_route_handler())
    barrier = result._claude_seo_native_barrier
    assert options['proxy']['bypass'] == '<-loopback>'
    assert options['proxy']['server'] == f'http://127.0.0.1:{barrier.getsockname()[1]}'
    assert barrier.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
    try:
        with pytest.raises(ConnectionRefusedError):
            socket.create_connection(barrier.getsockname(), timeout=1)
    finally:
        closed()
    assert barrier.fileno() == -1
