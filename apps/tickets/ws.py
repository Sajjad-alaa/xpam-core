"""XPAM: the live ticket pages' WebSocket (/ws/tickets/events/). A signed-in user receives {"type": "ticket_changed",
"id": <ticket id>} for each change of a ticket they may see — the same rule as the ticket lists
(Ticket.get_user_related_tickets: applicant, assignee, copied user, administrator of its organization, system
administrator) — and nothing else. The socket closes when its user is disabled or its login session ends.
"""
from channels.generic.websocket import JsonWebsocketConsumer

from common.utils import get_logger
from common.utils.ws_limit import UserSocketLimit
from common.utils.ws_thread import bind_server_loop
from users.models import User
from .models import Ticket
from .realtime import ticket_event_chan

logger = get_logger(__name__)

__all__ = ['TicketEventsWebsocket']

# (one shared socket per browser tab)
socket_limit = UserSocketLimit(20)


class TicketEventsWebsocket(JsonWebsocketConsumer):
    sub = None
    counted_user_id = None

    def connect(self):
        user = self.scope['user']
        if not user.is_authenticated:
            self.close()
            return
        if not socket_limit.acquire(user.id):
            logger.warning('Ticket events socket refused: too many open for user %s', user.id)
            self.close(code=4429)
            return
        self.counted_user_id = user.id
        self.accept()
        user_id = user.id
        session = self.scope.get('session')
        session_key = getattr(session, 'session_key', None)
        bind = bind_server_loop()

        def on_ticket_changed(msg):
            bind()  # (this runs in the Redis subscription thread: send on the server's loop)
            ticket_id = msg.get('id') if isinstance(msg, dict) else None
            if not ticket_id:
                return
            # a fresh copy each time: the user may have been disabled, signed out or lost a role since the page
            # opened (a socket signed in with a session ends with that session)
            current = User.objects.filter(id=user_id, is_active=True).first()
            if current is None or not current.is_valid or (session_key and not session.exists(session_key)):
                self.close()
                return
            if Ticket.get_user_related_tickets(current).filter(id=ticket_id).exists():
                self.send_json({'type': 'ticket_changed', 'id': ticket_id})

        self.sub = ticket_event_chan.subscribe(on_ticket_changed)

    def receive_json(self, content, **kwargs):
        pass  # (the page does not send anything)

    def disconnect(self, code):
        if self.sub:
            self.sub.unsubscribe()
            self.sub = None
        if self.counted_user_id is not None:
            socket_limit.release(self.counted_user_id)
            self.counted_user_id = None
