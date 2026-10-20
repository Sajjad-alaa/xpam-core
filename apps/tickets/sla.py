"""
XPAM: approval service levels for access requests.

remind_minutes    a waiting step is announced again to its approvers (e-mail + chat)
escalate_minutes  the administrators are added to the waiting step and told
expire_hours      a request nobody decided in time (or whose access window is already over) is closed
0 switches each of them off. Settings: Rules → Approval settings in the console.
"""
from django.core.cache import cache
from django.utils import timezone
from django.utils.translation import gettext as _

from common.utils import get_logger
from orgs.utils import tmp_to_root_org

logger = get_logger(__name__)


def _step_started(ticket, step):
    if step.level <= 1:
        return ticket.date_created
    prev = ticket.ticket_steps.filter(level=step.level - 1).first()
    return prev.date_updated if prev else ticket.date_created


def _comment(ticket, body):
    from tickets.models import Comment
    Comment.objects.create(ticket=ticket, body=body, user=None, user_display='XPAM', type='common')


def _notify(ticket, assignees, prefix):
    from tickets.tasks import xpam_send_approval_messages
    from tickets.utils import send_ticket_applied_mail_to_assignees
    try:
        send_ticket_applied_mail_to_assignees(ticket, assignees)
    except Exception as e:
        logger.warning('Approval reminder mail for %s failed: %s', ticket, e)
    from tickets.channels import deliveries
    if deliveries('', [], '', ''):  # (only when a chat channel is set up)
        xpam_send_approval_messages.delay(str(ticket.id), prefix=prefix)


def run():
    from tickets.channels import get_config
    from tickets.models import ApplyAssetTicket, TicketAssignee
    config = get_config()
    remind, escalate, expire = config['remind_minutes'], config['escalate_minutes'], config['expire_hours']
    now = timezone.now()
    summary = {'reminded': 0, 'escalated': 0, 'expired': 0}
    with tmp_to_root_org():
        # oldest first: with more than 500 open requests, none is skipped forever
        for ticket in ApplyAssetTicket.objects.filter(status='open').select_related('applicant') \
                .order_by('date_created')[:500]:
            step = ticket.current_step
            if not step:
                continue
            ended = ticket.apply_date_expired and ticket.apply_date_expired <= now
            too_old = expire and (now - ticket.date_created).total_seconds() > expire * 3600
            if ended or too_old:
                try:
                    _comment(ticket, _('Closed automatically: nobody approved the request in time')
                             if too_old else _('Closed automatically: the requested time is already over'))
                    ticket.close()
                    summary['expired'] += 1
                    # the requester is told (otherwise the request just disappears from "Waiting")
                    from tickets.utils import send_ticket_processed_mail_to_applicant
                    send_ticket_processed_mail_to_applicant(ticket, 'XPAM')
                except Exception as e:
                    logger.warning('Closing the expired request %s failed: %s', ticket, e)
                continue
            waited = (now - _step_started(ticket, step)).total_seconds() / 60
            key = f'xpam-approval-sla:{ticket.id}:{step.level}'
            done = cache.get(key) or set()
            if escalate and waited >= escalate and 'escalated' not in done:
                from accounts.jit.selfservice import _admin_ids
                present = set(step.ticket_assignees.values_list('assignee_id', flat=True))
                # never the requester, nor whoever approved an earlier step (four eyes)
                earlier = set(TicketAssignee.objects.filter(
                    step__ticket_id=ticket.id, step__level__lt=step.level, state='approved',
                ).values_list('assignee_id', flat=True))
                new = [uid for uid in _admin_ids(ticket)
                       if uid not in present and uid not in earlier and uid != ticket.applicant_id]
                if new:
                    TicketAssignee.objects.bulk_create([TicketAssignee(assignee_id=uid, step=step) for uid in new])
                _comment(ticket, _('Escalated: waiting for %s minutes; the administrators can approve now') % int(waited))
                from users.models import User
                _notify(ticket, list(User.objects.filter(id__in=new)) or ticket.current_assignees,
                        _('Escalated'))
                done |= {'escalated', 'reminded'}
                summary['escalated'] += 1
            elif remind and waited >= remind and 'reminded' not in done:
                _notify(ticket, ticket.current_assignees, _('Reminder'))
                done.add('reminded')
                summary['reminded'] += 1
            cache.set(key, done, 30 * 24 * 3600)
    if any(summary.values()):
        logger.info('Approval SLA: %s', summary)
    return summary
