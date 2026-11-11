# XPAM: announce ticket changes to the live ticket pages (tickets/realtime.py)
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from tickets.models import Comment, Ticket, TicketAssignee, TicketStep
from tickets.realtime import publish_ticket_changed

__all__ = ['on_ticket_changed', 'on_ticket_part_changed']


@receiver([post_save, post_delete], dispatch_uid='tickets.realtime.ticket')
def on_ticket_changed(sender, instance=None, **kwargs):
    # (every kind of ticket is a subclass of Ticket: the signal comes with the subclass as sender)
    if isinstance(instance, Ticket):
        publish_ticket_changed(instance.pk)


@receiver([post_save, post_delete], sender=TicketStep, dispatch_uid='tickets.realtime.step')
@receiver([post_save, post_delete], sender=Comment, dispatch_uid='tickets.realtime.comment')
def on_ticket_part_changed(sender, instance=None, **kwargs):
    publish_ticket_changed(getattr(instance, 'ticket_id', None))


@receiver([post_save, post_delete], sender=TicketAssignee, dispatch_uid='tickets.realtime.assignee')
def on_assignee_changed(sender, instance=None, **kwargs):
    step = getattr(instance, 'step', None)
    publish_ticket_changed(getattr(step, 'ticket_id', None))
