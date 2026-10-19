from celery import shared_task
from django.utils.translation import gettext_lazy as _

from ops.celery.decorator import register_as_period_task

__all__ = ['xpam_send_approval_messages', 'xpam_approval_sla_task']


@shared_task(verbose_name=_('Send approval messages to chat channels'))
def xpam_send_approval_messages(ticket_id, prefix=''):
    from .channels import send_for_ticket
    return send_for_ticket(ticket_id, prefix=prefix)


@shared_task(
    verbose_name=_('Approval reminders, escalation and expiry'),
    description=_('Reminds approvers of waiting requests, escalates them to the administrators and closes '
                  'requests that nobody approved in time. Runs every five minutes.')
)
@register_as_period_task(interval=300)
def xpam_approval_sla_task():
    from .sla import run
    return run()
