from channels.auth import AuthMiddlewareStack
from channels.db import database_sync_to_async
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
from django.core.handlers.asgi import ASGIRequest
from django.conf import settings
from django.utils.module_loading import import_string
from oauth2_provider.contrib.rest_framework import OAuth2Authentication

from authentication.backends.drf import (
    SignatureAuthentication,
    AccessTokenAuthentication
)
from notifications.urls.ws_urls import urlpatterns as notifications_urlpatterns
from ops.urls.ws_urls import urlpatterns as ops_urlpatterns
from settings.urls.ws_urls import urlpatterns as setting_urlpatterns
from terminal.urls.ws_urls import urlpatterns as terminal_urlpatterns
from common.utils import get_logger
import socket

logger = get_logger(__name__)

__all__ = ['urlpatterns', 'application']

urlpatterns = ops_urlpatterns + \
              notifications_urlpatterns + \
              setting_urlpatterns + \
              terminal_urlpatterns

if settings.XPACK_ENABLED:
    urlpatterns += import_string('xpack.urls.ws_urls.urlpatterns')


@database_sync_to_async
def get_signature_user(scope):
    headers = dict(scope["headers"])
    if not headers.get(b'authorization'):
        return
    if scope['type'] == 'websocket':
        scope['method'] = 'GET'
    # 因为 ws 使用的是 scope，所以需要转换成 request 对象，用于认证校验
    request = ASGIRequest(scope, None)
    backends = [SignatureAuthentication(),
                AccessTokenAuthentication(),
                OAuth2Authentication()]
    for backend in backends:
        try:
            result = backend.authenticate(request)
            if not result:
                continue
            user, _ = result
            if user:
                return user
        except Exception:
            logger.debug('WebSocket authentication failed for %s', backend.__class__.__name__)
    return None


class WsSignatureAuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        user = await get_signature_user(scope)
        if user:
            scope['user'] = user
        return await self.app(scope, receive, send)


class SocketContextMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        fno = self._extract_socket_fno(scope, receive)

        if fno:
            logger.debug(f"Successfully extracted FNO: {fno}")
            scope['fno'] = fno

        return await self.app(scope, receive, send)

    @staticmethod
    def _extract_socket_fno(scope, receive) -> int:
        try:
            transport = scope.get('extensions', {}).get('transport')
            if not transport and receive:
                protocol = getattr(receive, "__self__", None)
                if protocol:
                    transport = getattr(protocol, "transport", None)

            if transport:
                sock = transport.get_extra_info('socket')
                if sock:
                    return sock.fileno()

        except Exception as e:
            logger.error(f"Internal error during FNO extraction: {e}")

        return None


class WsOriginMiddleware:
    """ XPAM: a browser's WebSocket must come from XPAM's own pages (cross-site WebSocket hijacking: a page on
    another site, open in an administrator's browser, could otherwise connect with the administrator's cookies).
    Allowed: the Origin's host is the host the browser connected to (the gateway forwards it), or a name in DOMAINS
    or SITE_URL (DOMAINS=* allows any). A connection without an Origin header is not a browser page (components,
    clients) and carries its own credentials: allowed. Same-origin needs no configuration, so access by IP works. """

    def __init__(self, app):
        self.app = app

    @staticmethod
    def _hostname(value):
        from urllib.parse import urlsplit
        try:
            return (urlsplit(value if '://' in value else f'//{value}').hostname or '').lower()
        except ValueError:
            return ''

    def allowed_hosts(self):
        names = {name.strip().lower() for name in str(settings.DOMAINS or '').split(',') if name.strip()}
        if '*' in names:
            return None
        hosts = {self._hostname(name) for name in names}
        hosts.add(self._hostname(settings.SITE_URL or ''))
        return {h for h in hosts if h}

    async def __call__(self, scope, receive, send):
        headers = dict(scope.get('headers') or [])
        origin = headers.get(b'origin', b'').decode('latin-1').strip()
        if origin and origin != 'null':
            origin_host = self._hostname(origin)
            request_host = self._hostname(headers.get(b'host', b'').decode('latin-1'))
            allowed = self.allowed_hosts()
            if not origin_host or (origin_host != request_host and allowed is not None and origin_host not in allowed):
                logger.warning('WebSocket refused: origin %s for host %s', origin[:200], request_host)
                await send({'type': 'websocket.close', 'code': 4403})
                return
        elif origin == 'null':
            # (a sandboxed frame or a file: page: not one of XPAM's pages)
            await send({'type': 'websocket.close', 'code': 4403})
            return
        return await self.app(scope, receive, send)


application = ProtocolTypeRouter({
    # Django's ASGI application to handle traditional HTTP requests
    "http": SocketContextMiddleware(
        get_asgi_application()
    ),

    # WebSocket chat handler
    "websocket": WsOriginMiddleware(SocketContextMiddleware(
        WsSignatureAuthMiddleware(
            AuthMiddlewareStack(
                URLRouter(urlpatterns)
            )
        )
    )),
})
