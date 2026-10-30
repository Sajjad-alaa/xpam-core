from django.test import TestCase
from rest_framework.exceptions import ValidationError

from orgs.models import Organization
from orgs.utils import tmp_to_org
from rbac.builtin import BuiltinRole
from tickets.models import ApprovalRule, Ticket, TicketFlow
from users.models import User


class SelfApprovalTest(TestCase):
    """ A request a user opens is never approved by its applicant: when nobody else can approve it (and no rule
    approves it at once), opening it is refused and rolled back. """

    def setUp(self):
        BuiltinRole.sync_to_db()
        self.admin = User.objects.get(username='admin')

    def ticket(self, approver_ids):
        with tmp_to_org(Organization.default()):
            rule = ApprovalRule.objects.create(level=1, users={'type': 'ids', 'ids': [str(i) for i in approver_ids]})
            flow = TicketFlow.objects.create(name='self-approval-test', type='general')
            flow.rules.add(rule)
            return Ticket.objects.create(title='access', type='general', applicant=self.admin, flow=flow,
                                         org_id=Organization.default().id)

    def test_the_applicant_alone_cannot_approve(self):
        ticket = self.ticket([self.admin.id])
        with tmp_to_org(Organization.default()), self.assertRaises(ValidationError):
            ticket.open()

    def test_another_administrator_approves_instead(self):
        other = User.objects.create(username='other-admin', name='Other admin', email='other@example.com')
        other.system_roles.add_role_system_admin()
        ticket = self.ticket([self.admin.id])
        with tmp_to_org(Organization.default()):
            ticket.open()
            self.assertEqual(ticket.current_assignees, [other])

    def test_system_review_tickets_keep_the_last_resort(self):
        # (login/command review: refusing would lock a sole administrator out)
        ticket = self.ticket([self.admin.id])
        self.assertEqual(ticket.exclude_applicant([self.admin], self.admin), [self.admin])
