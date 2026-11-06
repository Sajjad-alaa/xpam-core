from types import SimpleNamespace

from django.test import TestCase


class VaultImportTest(TestCase):
    """ An account read from an external vault must not crash on the VaultConnection import. """

    def serializer(self, superuser=True):
        from accounts.serializers.account.account import AccountSerializer
        user = SimpleNamespace(is_superuser=superuser, has_perm=lambda p: superuser)
        return AccountSerializer(context={'request': SimpleNamespace(user=user)})

    def test_external_secret_with_an_unknown_connection_is_a_validation_error(self):
        import uuid
        from rest_framework import serializers
        attrs = {'secret_source': 'external', 'secret_ref': {'connection': str(uuid.uuid4()), 'path': 'a/b'}}
        with self.assertRaises(serializers.ValidationError):
            self.serializer()._validate_external_secret(attrs)

    def test_external_secret_with_an_active_connection_passes(self):
        from accounts.models import VaultConnection
        conn = VaultConnection.objects.create(name='batch-a-vault', type='hcp', config={})
        attrs = {'secret_source': 'external',
                 'secret_ref': {'connection': str(conn.id), 'path': 'team-x/app', 'field': 'password'}}
        out = self.serializer()._validate_external_secret(attrs)
        self.assertEqual(out['secret_ref']['path'], 'team-x/app')
        self.assertFalse(out['secret_reset'])

    def test_connection_type(self):
        from accounts.models import VaultConnection
        from accounts.serializers.account.account import AccountSerializer
        conn = VaultConnection.objects.create(name='batch-a-vault2', type='openbao', config={})
        self.assertEqual(AccountSerializer._connection_type(conn.id), 'openbao')


class CeleryWorkersTest(TestCase):
    def test_a_combined_worker_counts_as_both(self):
        from ops.celery.utils import _active_queue_workers
        self.assertEqual(_active_queue_workers(['ansible,celery@host']), {'ansible', 'celery'})

    def test_separate_workers(self):
        from ops.celery.utils import _active_queue_workers
        self.assertEqual(_active_queue_workers(['ansible@h1', 'celery@h1', None]), {'ansible', 'celery'})

    def test_a_single_worker_is_not_enough(self):
        from ops.celery.utils import _active_queue_workers
        self.assertEqual(len(_active_queue_workers(['celery@h1', 'celery@h2'])), 1)
