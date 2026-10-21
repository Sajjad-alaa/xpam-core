"""
XPAM high availability: tell the administrators that this server has become the primary (failover or
switchover). Run by the xpam-ha agent once XPAM is up on the new primary.
"""
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.utils.translation import gettext as _

from common.utils import get_logger

logger = get_logger(__name__)


class Command(BaseCommand):
    help = 'XPAM high availability: notify the administrators that this server became the primary'

    def add_arguments(self, parser):
        parser.add_argument('--node', required=True)
        parser.add_argument('--ip', default='')
        parser.add_argument('--peer', default='')
        parser.add_argument('--peer-reachable', default='')

    def handle(self, *args, **options):
        from users.models import User
        node, ip, peer = options['node'], options['ip'], options['peer']
        peer_ok = options['peer_reachable'] == '1'
        when = timezone.localtime().strftime('%Y-%m-%d %H:%M:%S %Z')
        subject = _('XPAM moved to server %s') % node
        message = _('High availability: at %(when)s server %(node)s (%(ip)s) became the primary and runs XPAM now. '
                    'The other server (%(peer)s) is %(state)s. Users signed in again; sessions that were open '
                    'on the other server ended.') % {
            'when': when, 'node': node, 'ip': ip, 'peer': peer or '-',
            'state': _('reachable: it is the standby now') if peer_ok else _('NOT reachable: check it'),
        }
        logger.warning('XPAM HA: %s', message)
        admins = list(User.get_super_admins())
        try:
            from xpack.notifications import send_site_message_to_admins
            send_site_message_to_admins(subject, message, force=True)
        except ImportError:
            from notifications.site_msg import SiteMessageUtil
            SiteMessageUtil.send_msg(subject=subject, message=message, user_ids=[str(u.id) for u in admins])
        emails = [u.email for u in admins if u.email and not u.email.endswith('.invalid')]
        if emails and settings.EMAIL_HOST:
            try:
                from common.tasks import send_mail_async
                send_mail_async(subject, message, emails, fail_silently=True)
            except Exception as e:
                logger.warning('XPAM HA: the e-mail to the administrators failed: %s', e)
        self.stdout.write('notified')
