"""Chromium Fetch interception, installed before targets leave startup pause.

Playwright routes only the first request of a native redirect chain. CDP Fetch
pauses every hop. Keep Chromium responsible for redirects, origin, cookies and
method changes; provide only the real, verified HTTP response for each request.
No browser TCP connection to an audit target is continued by this transport.
"""
from __future__ import annotations

import base64
import json
import weakref
from dataclasses import dataclass, field
from urllib.parse import urlparse

_transports = weakref.WeakKeyDictionary()
_REDIRECTS = {301, 302, 303, 307, 308}
_ROOT_FILTER = [
    {'type': 'tab', 'exclude': True},
    {'type': 'browser', 'exclude': True},
    {'type': 'iframe', 'exclude': True},
    {'type': 'worker', 'exclude': True},
    {},  # Related iframes/workers are attached recursively by their parent.
]
_CHILD_FILTER = [{'type': 'iframe'}, {'type': 'worker'}, {'exclude': True}]


@dataclass
class _Binding:
    target: str
    context: str
    flat_session: str | None = None
    ready: bool = False
    pending: list = field(default_factory=list)


@dataclass
class _Chain:
    count: int
    origin: tuple
    strip_authorization: bool = False


def _origin(url):
    parsed = urlparse(url)
    return parsed.scheme.lower(), parsed.hostname, parsed.port or (
        443 if parsed.scheme == 'https' else 80
    )


class _Request:
    def __init__(self, event, strip_authorization=False):
        request = event['request']
        self.url = request['url']
        self.method = request['method']
        self.resource_type = event.get('resourceType', 'Other').lower()
        self._headers = {
            name: value for name, value in request.get('headers', {}).items()
            if not (strip_authorization and name.lower() == 'authorization')
        }
        entries = request.get('postDataEntries')
        if entries is not None:
            # Never silently drop binary/upload bodies missing from CDP.
            self.post_data_buffer = b''.join(
                base64.b64decode(entry['bytes'], validate=True) for entry in entries
            )
        elif 'postData' in request:
            self.post_data_buffer = request['postData'].encode('utf-8')
        elif request.get('hasPostData'):
            raise ValueError('Request body unavailable to verified transport')
        else:
            self.post_data_buffer = None

    def all_headers(self):
        return dict(self._headers)


class _Route:
    supports_redirects = True

    def __init__(self, transport, path, event):
        self.transport, self.path, self.event = transport, path, event
        self.key = (path, event['requestId'])
        self.handled = False
        handler = transport.contexts.get(transport.bindings[path].context)
        self.failure_count = len(handler.failures) if handler else 0
        self.intentional_skip = False

    def abort(self):
        self.handled = True
        binding = self.transport.bindings.get(self.path)
        handler = self.transport.contexts.get(binding.context) if binding else None
        if handler and not self.intentional_skip and len(handler.failures) == self.failure_count:
            handler.failures.append('Browser request blocked by safety policy')
        self.transport.chains.pop(self.key, None)
        self.transport.send(self.path, 'Fetch.failRequest', {
            'requestId': self.event['requestId'], 'errorReason': 'BlockedByClient',
        })

    def continue_(self):
        # HTTP(S) must always use the verified Python transport.
        if urlparse(self.event['request']['url']).scheme in ('http', 'https'):
            self.abort()
            return
        self.handled = True
        self.transport.chains.pop(self.key, None)
        self.transport.send(self.path, 'Fetch.continueRequest', {
            'requestId': self.event['requestId'],
        })

    def fulfill(self, *, status, headers, body):
        response_headers = []
        for name, value in headers.items():
            values = value.split('\n') if name.lower() == 'set-cookie' else [value]
            response_headers.extend({'name': name, 'value': item} for item in values)
        redirect = status in _REDIRECTS and any(
            name.lower() == 'location' and value for name, value in headers.items()
        )
        if not redirect:
            self.transport.chains.pop(self.key, None)
        self.handled = True
        self.transport.send(self.path, 'Fetch.fulfillRequest', {
            'requestId': self.event['requestId'], 'responseCode': status,
            'responseHeaders': response_headers,
            'body': base64.b64encode(body).decode('ascii'),
        })


class _Transport:
    def __init__(self, browser, context_id, handler):
        self.root = browser.new_browser_cdp_session()
        self.contexts = {context_id: handler}
        self.bindings = {}
        self.targets = set()
        self.callbacks = {}
        self.chains = {}
        self.serial = 0
        self.closed = False
        self.root.on('Target.attachedToTarget', lambda event: self.attached((), event))
        self.root.on('Target.receivedMessageFromTarget', lambda event: self.message((), event))
        self.root.on('Target.detachedFromTarget', lambda event: self.detached((), event))
        # Browser-level auto-attach requires flat sessions. Hold that startup
        # pause until a separately attached, message-routed Fetch session is
        # fully configured. Other clients resuming their own sessions cannot
        # release this client's pause.
        try:
            self.root.send('Target.setAutoAttach', {
                'autoAttach': True, 'waitForDebuggerOnStart': True,
                'flatten': True, 'filter': _ROOT_FILTER,
            })
        except Exception:
            self.root.detach()
            raise
        browser.on('disconnected', self.shutdown)

    def send(self, path, method, params=None, callback=None):
        self.serial += 1
        command = {'id': self.serial, 'method': method, 'params': params or {}}
        self.callbacks[(path, self.serial)] = callback or (
            lambda result: self.command_result(path, method, params or {}, result)
        )
        for index in range(len(path) - 1, 0, -1):
            self.serial += 1
            # An envelope error belongs to the child, never its live parent.
            self.callbacks[(path[:index], self.serial)] = (
                lambda result: self.command_result(path, method, params or {}, result)
            )
            command = {'id': self.serial, 'method': 'Target.sendMessageToTarget',
                       'params': {'sessionId': path[index], 'message': json.dumps(command)}}
        self.root.send('Target.sendMessageToTarget', {
            'sessionId': path[0], 'message': json.dumps(command),
        })

    def command_result(self, path, method, params, result):
        if 'error' not in result or path not in self.bindings:
            return
        message = result['error'].get('message', '').lower().replace(' ', '')
        if method in ('Fetch.fulfillRequest', 'Fetch.failRequest') and any(
            marker in message for marker in ('invalidinterceptionid', 'invalidrequestid')
        ):
            # AbortController/navigation can cancel an already paused request.
            # It no longer exists, so do not kill the page or fall back to the network.
            self.chains.pop((path, params.get('requestId')), None)
            return
        self.fail_target(path, 'Chromium verified transport command failed')

    def message(self, parent, event):
        if self.closed:
            return
        path = parent + (event['sessionId'],)
        data = json.loads(event['message'])
        if 'id' in data:
            callback = self.callbacks.pop((path, data['id']), None)
            if callback:
                callback(data)
            elif 'error' in data and path in self.bindings:
                self.fail_target(path, 'Chromium verified transport command failed')
            return
        method, params = data.get('method'), data.get('params', {})
        if method == 'Target.attachedToTarget':
            self.attached(path, params)
        elif method == 'Target.receivedMessageFromTarget':
            self.message(path, params)
        elif method == 'Target.detachedFromTarget':
            self.detached(path, params)
        elif method == 'Fetch.requestPaused':
            self.paused(path, params)

    def attached(self, parent, event):
        info = event['targetInfo']
        context_id = info.get('browserContextId')
        if parent:
            binding = self.bindings.get(parent)
            context_id = context_id or (binding.context if binding else None)
        if context_id not in self.contexts:
            # Do not instrument unrelated browser contexts.
            if parent:
                self.send(parent, 'Target.detachFromTarget', {'sessionId': event['sessionId']})
            else:
                self.root.send('Target.detachFromTarget', {'sessionId': event['sessionId']})
            return
        target = info['targetId']
        if not parent and target in self.targets:
            return  # The explicit non-flat side attachment also emits this event.
        if info['type'] not in ('page', 'iframe', 'worker', 'shared_worker'):
            self.contexts[context_id].failures.append('Unsupported browser target blocked')
            self.root.send('Target.closeTarget', {'targetId': target})
            return
        self.targets.add(target)
        flat_session = None
        if not parent:
            flat_session = event['sessionId']
            try:
                session = self.root.send('Target.attachToTarget', {
                    'targetId': target, 'flatten': False,
                })['sessionId']
            except Exception:
                self.root.send('Target.closeTarget', {'targetId': target})
                raise
        else:
            session = event['sessionId']
        path = parent + (session,)
        self.bindings[path] = _Binding(target, context_id, flat_session)

        def enabled(result):
            if 'error' in result:
                # Worker loaders can be intercepted by their owning frame.
                # Some Chromium worker sessions do not expose Fetch at all.
                # They may run only behind the mandatory native-deny barrier:
                # any load not delivered to a verified agent fails, never
                # falls back to a real native connection.
                if info['type'] in ('worker', 'shared_worker'):
                    if info['type'] == 'shared_worker':
                        self.contexts[context_id].failures.append(
                            'Shared-worker Fetch interception unavailable; '
                            'loads not intercepted by a frame are denied by native egress barrier'
                        )
                    configured({'result': {}})
                    return
                self.fail_target(path, 'Browser target cannot enable verified Fetch interception')
                return
            self.send(path, 'Target.setAutoAttach', {
                'autoAttach': True, 'waitForDebuggerOnStart': True,
                'flatten': False, 'filter': _CHILD_FILTER,
            }, configured)

        def configured(result):
            if 'error' in result:
                self.fail_target(path, 'Browser target cannot guard child targets')
                return
            binding = self.bindings.get(path)
            if binding is None:
                return  # A cancelled/closed target must never be resumed.
            binding.ready = True
            try:
                pending, binding.pending = binding.pending, []
                for event in pending:
                    self.paused(path, event)
                if flat_session:
                    self.root.send('Target.detachFromTarget', {'sessionId': flat_session})
                self.send(path, 'Runtime.runIfWaitingForDebugger', {}, resumed)
            except Exception:
                self.fail_target(path, 'Browser target startup was cancelled')

        def resumed(result):
            if 'error' in result:
                self.fail_target(path, 'Browser target startup failed')
                return

        self.send(path, 'Fetch.enable', {
            'patterns': [{'urlPattern': '*', 'requestStage': 'Request'}],
        }, enabled)

    def paused(self, path, event):
        binding = self.bindings.get(path)
        if not binding or not binding.ready:
            if binding:
                # A popup's navigation can pause immediately after Fetch.enable,
                # before child-target setup finishes. Keep the request paused;
                # never continue it or close a legitimate pending navigation.
                if len(binding.pending) >= 128:
                    self.fail_target(path, 'Browser startup request queue exceeded its limit')
                else:
                    binding.pending.append(event)
            return  # Never continue an unowned/unready request.
        handler = self.contexts.get(binding.context)
        route = _Route(self, path, event)
        if handler is None:
            route.abort()
            return
        try:
            previous = event.get('redirectedRequestId')
            chain = self.chains.pop((path, previous), None) if previous else None
            if previous and chain is None:
                raise ValueError('Untracked browser redirect blocked')
            count = chain.count + 1 if chain else 0
            if count > handler.max_redirects:
                handler.failures.append('Browser redirect loop or maximum redirect count exceeded')
                route.abort()
                return
            current_origin = _origin(event['request']['url'])
            # Context-level extra headers can reappear on later hops. Once
            # credentials cross an origin boundary, never restore them in
            # this chain, including a subsequent return to the first origin.
            strip_authorization = bool(chain and (
                chain.strip_authorization or chain.origin != current_origin
            ))
            request = _Request(event, strip_authorization)
            self.chains[route.key] = _Chain(count, current_origin, strip_authorization)
            handler(route, request)  # Public DNS/SSRF/TLS policy before the HTTP request.
        except Exception:
            handler.failures.append('Browser request blocked by verified transport')
            if not route.handled:
                route.abort()

    def fail_target(self, path, diagnostic):
        binding = self.bindings.get(path)
        if binding:
            try:
                self.root.send('Target.getTargetInfo', {'targetId': binding.target})
            except Exception:
                return  # Normal cancellation/target destruction, not an active failure.
            handler = self.contexts.get(binding.context)
            if handler:
                handler.failures.append(diagnostic)
            try:
                self.root.send('Target.closeTarget', {'targetId': binding.target})
            except Exception:
                pass  # A closed/crashed target is already fail-closed.

    def detached(self, parent, event):
        prefix = parent + (event['sessionId'],)
        for path in list(self.bindings):
            if path[:len(prefix)] == prefix:
                binding = self.bindings.pop(path, None)
                if binding is None:
                    continue
                self.targets.discard(binding.target)
                # Loss of a guard must not leave a still-live target unguarded.
                try:
                    self.root.send('Target.getTargetInfo', {
                        'targetId': binding.target,
                    })
                except Exception:
                    pass  # Normal target destruction, not loss of a live guard.
                else:
                    handler = self.contexts.get(binding.context)
                    if handler:
                        handler.failures.append('Browser verified transport detached')
                    try:
                        self.root.send('Target.closeTarget', {'targetId': binding.target})
                    except Exception:
                        pass
        for mapping in (self.chains, self.callbacks):
            for key in list(mapping):
                if key[0][:len(prefix)] == prefix:
                    del mapping[key]

    def shutdown(self, *_args):
        self.closed = True
        self.callbacks.clear()
        self.chains.clear()
        self.bindings.clear()
        self.contexts.clear()


def install(browser, context, handler):
    """Identify an about:blank context, then guard every future target in it."""
    if not getattr(context, '_claude_seo_native_barrier', None):
        raise RuntimeError('Verified Chromium transport requires a native-deny barrier')
    probe = context.new_page()
    session = context.new_cdp_session(probe)
    try:
        context_id = session.send('Target.getTargetInfo')['targetInfo']['browserContextId']
    finally:
        session.detach()
        probe.close()
    transport = _transports.get(browser)
    if transport is None:
        transport = _Transport(browser, context_id, handler)
        _transports[browser] = transport
    else:
        transport.contexts[context_id] = handler
    context.on('close', lambda *_: transport.contexts.pop(context_id, None))
    context._claude_seo_cdp_transport = transport
