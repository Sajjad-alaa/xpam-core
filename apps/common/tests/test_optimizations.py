from unittest import mock

from django.test import TestCase
from rest_framework.test import APIClient

from orgs.models import Organization
from orgs.utils import tmp_to_org
from rbac.builtin import BuiltinRole
from users.models import User


class OptimizationsKeepBehaviourTest(TestCase):
    """ The October optimizations change how fast things are read, never what is read. """

    def setUp(self):
        BuiltinRole.sync_to_db()
        self.admin = User.objects.get(username='admin')
        User.objects.filter(pk=self.admin.pk).update(is_first_login=False)
        self.org = Organization.default()

    def host(self):
        from assets.models import Host, Platform
        with tmp_to_org(self.org):
            return Host.objects.create(name='opt-host', address='10.0.0.3', platform=Platform.objects.get(name='Linux'))

    def test_encrypted_values_read_back_the_same(self):
        from common.db.utils import Encryptor
        from common.utils.encode import signer
        User.objects.filter(pk=self.admin.pk).update(phone='+15550100', wechat='')
        user = User.objects.get(pk=self.admin.pk)
        self.assertEqual((user.phone, user.wechat), ('+15550100', ''))
        # an encrypted empty value is '' without the legacy signature check; a legacy signed value still opens
        with mock.patch.object(signer, 'unsign', wraps=signer.unsign) as unsign:
            self.assertEqual(Encryptor(Encryptor('').encrypt()).decrypt(), '')
            unsign.assert_not_called()
        self.assertEqual(Encryptor(signer.sign('legacy-value')).decrypt(), 'legacy-value')
        # an empty column (never written) is '' without decrypting
        from users.models import User as U
        field = U._meta.get_field('wechat')
        with mock.patch.object(Encryptor, 'decrypt') as decrypt:
            self.assertEqual(field.from_db_value('', None, None), '')
            decrypt.assert_not_called()

    def test_a_new_mfa_rule_is_seen_at_once_by_the_process_that_saved_it(self):
        from django.core.cache import cache
        from accounts.jit import policy
        from accounts.jit.policy import user_must_keep_mfa
        from accounts.models import JITPolicy

        def forget():  # (the cache is not rolled back with the test's database)
            cache.delete_many(['xpam-jit-mfa-policies', f'xpam-jit-mfa-user:{self.admin.id}'])
            policy._no_mfa_policies_until = 0.0
        forget()
        self.addCleanup(forget)
        self.assertFalse(user_must_keep_mfa(User.objects.get(pk=self.admin.pk)))
        with tmp_to_org(self.org):
            JITPolicy.objects.create(name='opt-mfa', require_mfa=True, is_active=True, scope='all',
                                     users={'type': 'ids', 'ids': [str(self.admin.id)]}, org_id=self.org.id)
        cache.delete(f'xpam-jit-mfa-user:{self.admin.id}')  # (the per-user answer is cached for a minute, as before)
        self.assertTrue(user_must_keep_mfa(User.objects.get(pk=self.admin.pk)))

    def test_the_account_list_does_not_load_secrets_but_the_secret_api_does(self):
        from accounts.models import Account
        from accounts.serializers import AccountSecretSerializer, AccountSerializer
        asset = self.host()
        with tmp_to_org(self.org):
            Account.objects.create(asset=asset, name='opt-acc', username='root', secret_type='password',
                                   secret='S3cret-value-1')
            listed = AccountSerializer.setup_eager_loading(Account.objects.filter(asset=asset)).get()
            read = AccountSecretSerializer.setup_eager_loading(Account.objects.filter(asset=asset)).get()
        self.assertIn('_secret', listed.get_deferred_fields())
        self.assertNotIn('_secret', read.get_deferred_fields())
        self.assertEqual(read.secret, 'S3cret-value-1')
        client = APIClient(HTTP_HOST='localhost')
        client.force_authenticate(self.admin)
        r = client.get(f'/api/v1/accounts/accounts/?asset={asset.id}&limit=10', HTTP_X_JMS_ORG=str(self.org.id))
        self.assertEqual(r.status_code, 200)
        self.assertNotIn('S3cret-value-1', r.content.decode())

    def test_the_cached_org_membership_follows_role_changes_at_once(self):
        from types import SimpleNamespace
        from orgs.middleware import OrgMiddleware
        from rbac.models import OrgRoleBinding
        other = Organization.objects.create(name='opt-other-org')
        user = User.objects.create(username='opt-member', name='Opt member', email='opt-member@example.com')
        with tmp_to_org(self.org):
            user.org_roles.add(BuiltinRole.org_user.get_role())

        def usable():
            request = SimpleNamespace(path='/api/v1/users/profile/', user=User.objects.get(pk=user.pk))
            return OrgMiddleware.usable_org(request, other)

        self.assertNotEqual(usable().id, other.id)          # (not a member: falls back)
        self.assertNotEqual(usable().id, other.id)          # (now from the cache)
        with tmp_to_org(other):
            user.org_roles.add(BuiltinRole.org_user.get_role())
        self.assertEqual(usable().id, other.id)             # (added: usable at once)
        with tmp_to_org(other):
            OrgRoleBinding.objects.filter(user=user, org=other).delete()
        self.assertNotEqual(usable().id, other.id)          # (removed: refused at once)

    def test_the_server_size_follows_the_server_unless_configured(self):
        from xpam.settings import custom
        memory = lambda gb: mock.Mock(total=gb * 1024 ** 3)
        cases = [((2, 16), 'small'), ((4, 6), 'small'), ((4, 7.5), 'medium'), ((16, 8), 'medium'), ((8, 16), 'large')]
        for (cpus, gb), size in cases:
            with mock.patch.dict('os.environ', {'SERVER_SIZE': 'auto'}), \
                    mock.patch('psutil.cpu_count', return_value=cpus), \
                    mock.patch('psutil.virtual_memory', return_value=memory(gb)):
                self.assertEqual(custom._server_size(), size, (cpus, gb))
        with mock.patch.dict('os.environ', {'SERVER_SIZE': 'large'}), mock.patch('psutil.cpu_count', return_value=2):
            self.assertEqual(custom._server_size(), 'large')
