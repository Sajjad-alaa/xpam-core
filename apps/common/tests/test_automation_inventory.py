import json
import os
import tempfile

from django.test import TestCase

from orgs.models import Organization
from orgs.utils import tmp_to_org


class AutomationInventoryTest(TestCase):
    """ Every account automation (push, change secret, removal, verification, discovery, JIT) starts by writing the
    Ansible inventory: it crashed in 5.1.27-5.1.31 (a helper moved by an upstream backport). """

    def setUp(self):
        from assets.models import Host, Platform
        from accounts.models import Account
        self.org = Organization.default()
        with tmp_to_org(self.org):
            self.platform = Platform.objects.get(name='Linux')
            self.asset = Host.objects.create(name='inv-host', address='10.0.0.4', platform=self.platform)
            self.account = Account.objects.create(asset=self.asset, name='root', username='root',
                                                  secret_type='password', secret='Pass{{ evil }}word1', privileged=True)

    def test_the_inventory_is_written_and_user_values_are_escaped(self):
        from ops.ansible import JMSInventory
        path = os.path.join(tempfile.mkdtemp(), 'hosts.json')
        with tmp_to_org(self.org):
            inventory = JMSInventory([self.asset], account_policy='privileged_first', host_callback=None)
            inventory.write_to_file(path)
        with open(path) as f:
            text = f.read()
        data = json.loads(text)
        host = next(h for h in data['all']['hosts'].values() if h.get('jms_asset', {}).get('name') == 'inv-host')
        self.assertEqual(host['jms_asset']['platform'], 'Linux')
        self.assertNotIn('{{ evil }}', text)   # (the password reaches Ansible escaped, never as a template)
