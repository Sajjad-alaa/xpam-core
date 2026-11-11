"""XPAM: the live ticket pages' WebSocket (/ws/tickets/events/). A signed-in user receives {"type": "ticket_changed",
"id": <ticket id>} for each change of a ticket they may see — the same rule as the ticket lists
(Ticket.get_user_related_tickets: applicant, assignee, copied user, administrator of its organization, system
administrator) — and nothing else.
"""
from channels.generic.websocket import JsonWebsocketConsumer

from common.utils import get_logger
from users.models import User
from .models import Ticket
from .realtime import ticket_event_chan

logger = get_logger(__name__)

__all__ = ['TicketEventsWebsocket']


class TicketEventsWebsocket(JsonWebsocketConsumer):
    sub = None

    def connect(self):
        user = self.scope['user']
        if not user.is_authenticated:
            self.close()
            return
        self.accept()
        user_id = user.id

        def on_ticket_changed(msg):
            ticket_id = msg.get('id') if isinstance(msg, dict) else None
            if not ticket_id:
                return
            # a fresh copy each time: the user may have been disabled or lost a role since the page opened
            current = User.objects.filter(id=user_id, is_active=True).first()
            if current is None or not current.is_valid:
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
