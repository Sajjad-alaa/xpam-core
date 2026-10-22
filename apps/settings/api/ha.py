"""
XPAM: high availability status and planned switchover (System settings -> High availability).

The cluster is managed outside the application (Patroni + etcd decide which server is primary, the
xpam-ha agent on each server follows). XPAM itself has no access to the cluster (Patroni's API needs the
cluster certificate, which stays with the agent): this view reads the status file the agent writes into
XPAM's data folder, and asks for a switchover by writing a request the agent carries out.
"""
import json
import os
import time

from django.utils.translation import gettext as _
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response

__all__ = ['HAStatusApi', 'HASwitchoverApi', 'ha_alerts']

HA_DIR = '/opt/jumpserver/data/ha'
STATUS_FILE = os.path.join(HA_DIR, 'status.json')
REQUEST_FILE = os.path.join(HA_DIR, 'request.json')


def ha_enabled():
    return os.environ.get('HA_ENABLED') == '1'


def _agent():
    try:
        with open(STATUS_FILE) as f:
            status = json.load(f)
        status['age'] = int(time.time()) - int(status.get('updated') or 0)
        return status
    except (OSError, ValueError):
        return None


def _cluster_id():
    """ the ID the cluster licence names (with every server's ID, shown per member) """
    try:
        from xpack.utils import get_cluster_id
        return get_cluster_id()
    except Exception:
        return ''


def _in_sync(members):
    return any(m.get('role') == 'sync_standby' and m.get('state') == 'streaming' for m in members or [])


def ha_alerts():
    """Banner alerts for administrators when the cluster is not fully protected ([] when it is)."""
    if not ha_enabled():
        return []
    alert = lambda key, level, title, message: {  # noqa: E731
        'id': f'ha_{key}', 'category': 'ha', 'level': level, 'title': title, 'message': message,
        'action_label': _('High availability'), 'action_path': '/settings/high-availability'}
    agent = _agent()
    if not agent or agent.get('age', 999) > 60:
        return [alert('agent', 'warning', _('High availability: the agent does not report'),
                      _('Run "systemctl status xpam-ha" on this server.'))]
    out = []
    if agent.get('members') is None:
        out.append(alert('cluster', 'danger', _('High availability: the database cluster does not answer'),
                         _('Run "xpamctl ha status" on the servers.')))
    elif not _in_sync(agent.get('members')):
        out.append(alert('no_standby', 'danger', _('High availability: no standby in sync'),
                         _('If this server fails now, XPAM does not move to the other server by itself. '
                           'Check the other server ("xpamctl ha status").')))
    if agent.get('witness_reachable') is False:
        out.append(alert('witness', 'warning', _('High availability: the witness does not answer'),
                         _('XPAM keeps running, but a second failure would stop the automatic failover. '
                           'Bring the witness (%s) back.') % agent.get('witness_ip', '')))
    vault = agent.get('vault') or {}
    vault_nodes = vault.get('nodes') or []
    if vault_nodes:
        healthy = [n for n in vault_nodes if n.get('state') == 'ok']
        if not healthy:
            out.append(alert('vault', 'danger', _('High availability: no Vault server answers'),
                             _("XPAM keeps running with the secrets it has read, but cannot start again or read "
                               "account passwords until Vault answers.")))
        elif len(healthy) < len(vault_nodes):
            out.append(alert('vault', 'warning', _('High availability: a Vault server is down or sealed'),
                             _('%(down)s — unseal it (xpam-vault.sh unseal) or bring it back.')
                             % {'down': ', '.join(f"{n['addr']} ({n['state']})" for n in vault_nodes
                                                  if n.get('state') != 'ok')}))
    fs = agent.get('file_sync') or {}
    if fs.get('ok') is False:
        out.append(alert('files', 'warning', _('High availability: recordings are not copied to the standby'),
                         _('The last copy failed: %s') % (fs.get('error') or '-')[:200]))
    return out


class HAStatusApi(GenericAPIView):
    rbac_perms = {'GET': 'settings.view_setting'}

    def get(self, request):
        if not ha_enabled():
            return Response({'enabled': False})
        agent = _agent()
        data = {'enabled': True, 'this_node': os.environ.get('HA_NODE_NAME', ''), 'agent': agent,
                'members': (agent or {}).get('members') or [], 'error': '', 'cluster_id': _cluster_id()}
        if not agent:
            data['error'] = _('The high availability agent has not reported yet (systemctl status xpam-ha)')
        elif agent.get('members') is None:
            data['error'] = _('The database cluster does not answer (xpamctl ha status)')
        return Response(data)


class HASwitchoverApi(GenericAPIView):
    rbac_perms = {'POST': 'settings.change_setting'}

    def post(self, request):
        if not request.user.is_superuser:
            return Response({'detail': _('Only administrators can switch the primary server')}, status=403)
        if not ha_enabled():
            return Response({'detail': _('High availability is not enabled')}, status=400)
        agent = _agent()
        members = (agent or {}).get('members') or []
        candidate = next((m['name'] for m in members if m.get('role') == 'sync_standby'
                          and m.get('state') == 'streaming'), None)
        if not agent or agent.get('age', 999) > 60 or agent.get('role') != 'primary' or not candidate:
            return Response({'detail': _('There is no standby in sync to switch to (see the status below)')},
                            status=400)
        # the agent of this server (the primary) carries it out within a few seconds
        tmp = REQUEST_FILE + '.tmp'
        with open(tmp, 'w') as f:
            json.dump({'action': 'switchover', 'by': str(request.user), 'time': time.time()}, f)
        os.replace(tmp, REQUEST_FILE)
        return Response({'leader': candidate,
                         'detail': _('%s becomes the primary in a few seconds; XPAM moves there in about a minute')
                         % candidate})
