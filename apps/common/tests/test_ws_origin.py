import asyncio

from django.test import SimpleTestCase, override_settings

from jumpserver.routing import WsOriginMiddleware


def connect(origin=None, host='xpam.example.com'):
    """ (passed, close code) of a WebSocket handshake through the origin check """
    reached, sent = [], []

    async def app(scope, receive, send):
        reached.append(True)

    async def send(message):
        sent.append(message)

    headers = [(b'host', host.encode())]
    if origin is not None:
        headers.append((b'origin', origin.encode()))
    asyncio.run(WsOriginMiddleware(app)({'type': 'websocket', 'headers': headers}, None, send))
    return bool(reached), (sent[0].get('code') if sent else None)


@override_settings(DOMAINS='', SITE_URL='http://127.0.0.1')
class WsOriginTest(SimpleTestCase):
    """ A browser WebSocket must come from XPAM's own pages (cross-site WebSocket hijacking). """

    def test_same_origin_passes(self):
        self.assertEqual(connect('https://xpam.example.com'), (True, None))

    def test_access_by_ip_with_a_port_passes_without_configuration(self):
        self.assertEqual(connect('https://192.168.15.21:8443', host='192.168.15.21'), (True, None))

    def test_another_site_is_refused(self):
        self.assertEqual(connect('https://evil.example.net'), (False, 4403))

    def test_a_null_origin_is_refused(self):
        self.assertEqual(connect('null'), (False, 4403))

    def test_no_origin_is_not_a_browser_page(self):
        self.assertEqual(connect(None), (True, None))

    @override_settings(DOMAINS='portal.example.org,xpam.example.com')
    def test_a_configured_domain_passes(self):
        self.assertEqual(connect('https://portal.example.org'), (True, None))

    @override_settings(DOMAINS='*')
    def test_domains_star_allows_any_origin(self):
        self.assertEqual(connect('https://anything.example.net'), (True, None))
