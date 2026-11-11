"""XPAM: live ticket pages. When a ticket changes (opened, approved, rejected, closed, a step or a comment), the
ticket's id is published on a Redis channel once the transaction commits. Each open ticket page holds a WebSocket
(tickets/ws.py) that passes the event on only to a user who may see that ticket, and the page then reloads its data
through the normal, permission-checked API: no ticket content travels over the socket.
"""
import threading

from django.db import transaction
from django.utils.functional import LazyObject

from common.utils import get_logger
from common.utils.connection import RedisPubSub

logger = get_logger(__name__)

__all__ = ['ticket_event_chan', 'publish_ticket_changed']


class TicketEventChannel(LazyObject):
    def _setup(self):
        self._wrapped = RedisPubSub('tickets.TicketChanged')


ticket_event_chan = TicketEventChannel()

# ticket ids already announced in the current transaction (an approval saves the ticket, its step and its assignees)
_pending = threading.local()


def _send(ticket_id):
    pending = getattr(_pending, 'ids', None)
    if pending is not None:
        pending.discard(ticket_id)
    try:
        ticket_event_chan.publish({'id': ticket_id})
    except Exception as e:  # a page that is not refreshed is not worth failing the change for
        logger.warning('Ticket change not announced: %s', e)


def publish_ticket_changed(ticket_id):
    if not ticket_id:
        return
    ticket_id = str(ticket_id)
    pending = getattr(_pending, 'ids', None)
    if pending is None:
        pending = _pending.ids = set()
    if ticket_id in pending:
        return
    pending.add(ticket_id)
    transaction.on_commit(lambda: _send(ticket_id))
