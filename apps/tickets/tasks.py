from celery import shared_task
from django.utils.translation import gettext_lazy as _

__all__ = ['xpam_send_approval_messages']


@shared_task(verbose_name=_('Send approval messages to chat channels'))
def xpam_send_approval_messages(ticket_id):
    from .channels import send_for_ticket
    return send_for_ticket(ticket_id)
