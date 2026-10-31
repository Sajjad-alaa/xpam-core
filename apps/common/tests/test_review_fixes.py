import os
import uuid
from datetime import timedelta
from io import StringIO
from types import SimpleNamespace
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from orgs.models import Organization
from orgs.utils import tmp_to_org
from rbac.builtin import BuiltinRole
from users.models import User


class ReviewFixesTest(TestCase):
    """ The findings of the October security review that held up. """

    def setUp(self):
        BuiltinRole.sync_to_db()
        self.admin = User.objects.get(username='admin')
        self.org = Organization.default()

    def host(self, name='review-host'):
        from assets.models import Host, Platform
        with tmp_to_org(self.org):
            return Host.objects.create(name=name, address='10.0.0.1', platform=Platform.objects.get(name='Linux'))

    def test_an_unlock_token_must_match_every_binding_it_names(self):
        # (a license_id the active license does not have used to match nothing and pass)
        from xpack import utils
        now = timezone.now()
        old_license = {'serial_no': 'XPAM-OLD-0001'}  # (licences issued before license_id existed)
        with mock.patch.object(utils, 'get_default_license', return_value=old_license):
            ok, msg = utils.apply_clock_unlock_token({
                'type': 'clock_unlock', 'installation_id': utils.get_system_installation_id(),
                'created_at': (now - timedelta(hours=1)).isoformat(),
                'expires_at': (now + timedelta(days=1)).isoformat(),
                'license_id': 'not-the-active-license', 'token_id': str(uuid.uuid4()),
            })
        self.assertFalse(ok)
        self.assertIn('mismatch', msg)

    def test_an_ended_access_cannot_be_extended(self):
        # (an expired or revoked access, extended under an auto-approving rule, came back as a new access)
        from accounts.jit.selfservice import SelfServiceError, extend
        from perms.models import AssetPermission
        with tmp_to_org(self.org):
            perm = AssetPermission.objects.create(
                name='review-ended', from_ticket=True, date_start=timezone.now() - timedelta(days=2),
                date_expired=timezone.now() - timedelta(hours=1), org_id=self.org.id)
            perm.users.add(self.admin)
        with self.assertRaisesMessage(SelfServiceError, 'ended'):
            extend(SimpleNamespace(user=self.admin), str(perm.id), 2)
        with tmp_to_org(self.org):
            AssetPermission.objects.filter(id=perm.id).update(date_expired=timezone.now() + timedelta(hours=3),
                                                             is_active=False)
        with self.assertRaisesMessage(SelfServiceError, 'ended'):
            extend(SimpleNamespace(user=self.admin), str(perm.id), 2)

    def test_network_device_passwords_cannot_add_commands(self):
        from libs.ansible.modules_utils.network_device import CiscoNXOS, DeviceError, FortiGate
        nxos = object.__new__(CiscoNXOS)
        with mock.patch.object(CiscoNXOS, 'configure') as configure:
            with self.assertRaises(DeviceError):
                nxos.create_user('ops', 'Abc123;feature bash-shell', 'read_only')
            with self.assertRaises(DeviceError):
                nxos.set_password('ops', 'Abc123;feature bash-shell')
            configure.assert_not_called()
        forti = object.__new__(FortiGate)
        with mock.patch.object(FortiGate, 'user') as user:
            with self.assertRaises(DeviceError):
                forti.change('admin', 'NewPass123', old_password='old"\nconfig system global')
            user.assert_not_called()

    def test_device_command_values_cannot_break_the_line(self):
        from accounts.jit.targets import TargetError, _device_commands
        self.assertEqual(_device_commands('user {username} pass {password}', {'username': 'a', 'password': 'b'}),
                         ['user a pass b'])
        with self.assertRaises(TargetError):
            _device_commands('enable {login_password}', {'login_password': 'x\nreload'})

    def test_import_update_keeps_the_user_name(self):
        from accounts.models import Account
        from accounts.serializers import AccountSerializer
        asset = self.host()
        with tmp_to_org(self.org):
            Account.objects.create(asset=asset, name='review-acc', username='root', secret_type='password')
            instance, stat = AccountSerializer.do_create({
                'asset': asset, 'name': 'review-acc', 'username': 'someone-else', 'secret_type': 'password',
                'on_invalid': 'update',
            })
        self.assertEqual(stat, 'updated')
        instance.refresh_from_db()
        self.assertEqual(instance.username, 'root')

    def test_secret_key_rotation_refuses_vault_secrets_without_a_data_key(self):
        # (they are in the vault encrypted with SECRET_KEY, and the rotation does not reach them)
        from accounts.models import Account
        asset = self.host()
        with tmp_to_org(self.org):
            acc = Account.objects.create(asset=asset, name='review-vault', username='vault', secret_type='password',
                                         secret='x')
        Account._base_manager.filter(pk=acc.pk).update(_secret='# Secret-has-been-saved-to-vault #')
        with mock.patch.dict(os.environ, {'NEW_SECRET_KEY': 'n' * 40}):
            with self.assertRaisesMessage(CommandError, 'kept in a vault'):
                call_command('rotate_secret_key', '--dry-run', stdout=StringIO())
