"""
XPAM: is this installation protected? One answer for the console (dashboard card, the High availability and
Account storage pages): high availability on or off and its state, Vault on or off — where XPAM's own
secrets are, where account secrets are kept, the data key — and whether the vault answers.
"""
import os

from django.conf import settings
from django.core.cache import cache
from django.utils.translation import gettext as _
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response

from .ha import _agent, _in_sync, ha_alerts, ha_enabled

__all__ = ['ProtectionStatusApi', 'protection_status']

XPAM_SECRETS_FILE = '/run/xpam-secrets/env'
VAULT_CHECK_CACHE_KEY = 'XPAM_PROTECTION_VAULT_CHECK'
VAULT_NAMES = {
    'hcp': 'HashiCorp Vault', 'azure': 'Azure Key Vault', 'aws': 'AWS Secrets Manager', 'openbao': 'OpenBao',
    'cyberark': 'CyberArk Conjur', 'delinea': 'Delinea Secret Server', 'gcp': 'Google Secret Manager',
}


def _ha():
    if not ha_enabled():
        return {'enabled': False}
    agent = _agent() or {}
    members = agent.get('members') or []
    leader = next((m for m in members if m.get('role') in ('leader', 'standby_leader')), {})
    return {
        'enabled': True,
        'this_node': os.environ.get('HA_NODE_NAME', ''),
        'role': agent.get('role') or '',
        'primary': leader.get('name', ''),
        'standby_in_sync': _in_sync(members),
        'witness_reachable': agent.get('witness_reachable'),
        'agent_reporting': bool(agent) and agent.get('age', 999) <= 60,
        'alerts': len(ha_alerts()),
    }


def _vault_check():
    """ the account vault answers (XPAM's own login and rights); cached a minute — the test logs in """
    result = cache.get(VAULT_CHECK_CACHE_KEY)
    if result is None:
        from accounts.backends import get_vault_client
        config = {k: getattr(settings, k) for k in dir(settings) if k.startswith('VAULT_')}
        try:
            ok, error = get_vault_client(raise_exception=True, **config).is_active()
        except Exception as e:
            ok, error = False, str(e)
        result = {'ok': bool(ok), 'error': '' if ok else str(error)[:200]}
        cache.set(VAULT_CHECK_CACHE_KEY, result, 60)
    return result


def _vault():
    from common.db import datakey
    secrets_from_vault = os.environ.get('XPAM_SECRETS_FROM_VAULT') == '1' or os.path.exists(XPAM_SECRETS_FILE)
    backend = settings.VAULT_BACKEND if settings.VAULT_ENABLED else ''
    try:
        data_key = datakey.provider()
    except Exception:
        data_key = 'unknown'
    data = {
        'enabled': bool(secrets_from_vault or settings.VAULT_ENABLED),
        'secrets_from_vault': secrets_from_vault,
        'account_storage': backend,
        'account_storage_name': VAULT_NAMES.get(backend, backend),
        'locked': bool(settings.VAULT_LOCKED),
        'data_key': data_key,
        'servers': ((_agent() or {}).get('vault') or {}).get('nodes') or [],
    }
    if settings.VAULT_ENABLED:
        data['check'] = _vault_check()
    return data


def protection_status():
    data = {'ha': _ha(), 'vault': _vault()}
    vault, ha = data['vault'], data['ha']
    problems = []
    if ha['enabled'] and (ha['alerts'] or not ha['agent_reporting']):
        problems.append(_('High availability needs attention'))
    if vault.get('check') and not vault['check']['ok']:
        problems.append(_('The vault does not answer'))
    data['problems'] = problems
    return data


class ProtectionStatusApi(GenericAPIView):
    rbac_perms = {'GET': 'settings.view_setting'}

    def get(self, request):
        return Response(protection_status())
