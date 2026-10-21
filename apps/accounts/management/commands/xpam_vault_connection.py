"""
XPAM: vault connections made on the server (managed: the console can see and test them, not change them).
  manage.py xpam_vault_connection add --name NAME --type TYPE [--update] [--test] < settings.json
  manage.py xpam_vault_connection list
  manage.py xpam_vault_connection remove --name NAME
The settings ({"VAULT_<TYPE>_...": "..."}) come on stdin: never on a command line.
"""
import json
import sys

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Vault connections managed on the server'

    def add_arguments(self, parser):
        parser.add_argument('action', choices=['add', 'list', 'remove'])
        parser.add_argument('--name')
        parser.add_argument('--type')
        parser.add_argument('--update', action='store_true')
        parser.add_argument('--test', action='store_true')

    def handle(self, *args, **options):
        from accounts.backends import get_vault_client
        from accounts.const import VaultTypeChoices
        from accounts.models import VaultConnection
        action = options['action']
        if action == 'list':
            for c in VaultConnection.objects.all():
                self.stdout.write(f'{c.id}  {c.name:24} {c.type:10} {"managed" if c.managed else "console":8} '
                                  f'{"active" if c.is_active else "inactive"}')
            return
        name = options.get('name') or ''
        if not name:
            raise CommandError('--name is required')
        if action == 'remove':
            deleted, _ = VaultConnection.objects.filter(name=name).delete()
            if not deleted:
                raise CommandError(f'no connection {name}')
            self.stdout.write(f'removed {name}')
            return
        vtype = options.get('type') or ''
        if vtype not in VaultTypeChoices.values or vtype == VaultTypeChoices.local:
            raise CommandError(f'--type: one of {", ".join(v for v in VaultTypeChoices.values if v != "local")}')
        try:
            config = json.loads(sys.stdin.read() or '{}')
        except ValueError as e:
            raise CommandError(f'settings: not JSON ({e})')
        prefix = f'VAULT_{vtype.upper()}_'
        wrong = [k for k in config if not k.startswith(prefix)]
        if wrong:
            raise CommandError(f'settings: only {prefix}*: {", ".join(wrong)}')
        existing = VaultConnection.objects.filter(name=name).first()
        if existing and not options['update']:
            raise CommandError(f'{name} exists (--update to replace its settings)')
        if options['test']:
            kwargs = dict(config, VAULT_ENABLED=True, VAULT_BACKEND=vtype)
            ok, error = get_vault_client(raise_exception=True, **kwargs).is_active()
            if not ok:
                raise CommandError(f'test failed: {error}')
        if existing:
            existing.type, existing.config, existing.managed = vtype, config, True
            existing.save()
            connection = existing
        else:
            connection = VaultConnection.objects.create(name=name, type=vtype, config=config, managed=True)
        self.stdout.write(f'{connection.id}  {name} ({vtype}) ready')
