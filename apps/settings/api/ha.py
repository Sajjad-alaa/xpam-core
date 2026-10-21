"""
XPAM: high availability status and planned switchover (System settings -> High availability).

The cluster is managed outside the application (Patroni + etcd decide which server is primary, the
xpam-ha agent on each server follows): this view only reads Patroni's REST API on the local database
container and the agent's status file, and asks Patroni for a switchover.
"""
import json
import os
import time

import requests
from django.utils.translation import gettext as _
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response

__all__ = ['HAStatusApi', 'HASwitchoverApi', 'ha_alerts']

PATRONI = 'http://postgresql:8008'
STATUS_FILE = '/opt/jumpserver/data/ha/status.json'


def ha_enabled():
    return os.environ.get('HA_ENABLED') == '1'


def _cluster():
    r = requests.get(f'{PATRONI}/cluster', timeout=5)
    r.raise_for_status()
    return r.json()


def _agent():
    try:
        with open(STATUS_FILE) as f:
            status = json.load(f)
        status['age'] = int(time.time()) - int(status.get('updated') or 0)
        return status
    except (OSError, ValueError):
        return None


def ha_alerts():
    """Banner alerts for administrators when the cluster is not fully protected ([] when it is)."""
    if not ha_enabled():
        return []
    alert = lambda key, level, title, message: {  # noqa: E731
        'id': f'ha_{key}', 'category': 'ha', 'level': level, 'title': title, 'message': message,
        'action_label': _('High availability'), 'action_path': '/settings/high-availability'}
    out = []
    try:
        members = _cluster().get('members', [])
    except Exception:
        return [alert('cluster', 'danger', _('High availability: the database cluster does not answer'),
                      _('XPAM cannot read the cluster state. Run "xpamctl ha status" on the servers.'))]
    if not any(m.get('role') == 'sync_standby' and m.get('state') == 'streaming' for m in members):
        out.append(alert('no_standby', 'danger', _('High availability: no standby in sync'),
                         _('If this server fails now, XPAM does not move to the other server by itself. '
                           'Check the other server ("xpamctl ha status").')))
    agent = _agent()
    if not agent or agent.get('age', 999) > 60:
        out.append(alert('agent', 'warning', _('High availability: the agent does not report'),
                         _('Run "systemctl status xpam-ha" on this server.')))
    else:
        if agent.get('witness_reachable') is False:
            out.append(alert('witness', 'warning', _('High availability: the witness does not answer'),
                             _('XPAM keeps running, but a second failure would stop the automatic failover. '
                               'Bring the witness (%s) back.') % agent.get('witness_ip', '')))
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
        data = {'enabled': True, 'this_node': os.environ.get('HA_NODE_NAME', ''), 'members': [],
                'agent': _agent(), 'error': ''}
        try:
            cluster = _cluster()
            for m in cluster.get('members', []):
                data['members'].append({
                    'name': m.get('name'), 'host': m.get('host'), 'role': m.get('role'), 'state': m.get('state'),
                    'lag': m.get('lag'), 'timeline': m.get('timeline'),
                })
        except Exception as e:
            data['error'] = _('The database cluster does not answer: %s') % str(e)[:200]
        return Response(data)


class HASwitchoverApi(GenericAPIView):
    rbac_perms = {'POST': 'settings.change_setting'}

    def post(self, request):
        if not request.user.is_superuser:
            return Response({'detail': _('Only administrators can switch the primary server')}, status=403)
        if not ha_enabled():
            return Response({'detail': _('High availability is not enabled')}, status=400)
        try:
            members = _cluster().get('members', [])
        except Exception as e:
            return Response({'detail': _('The database cluster does not answer: %s') % str(e)[:200]}, status=503)
        leader = next((m['name'] for m in members if m.get('role') == 'leader'), None)
        candidate = next((m['name'] for m in members if m.get('role') == 'sync_standby'
                          and m.get('state') == 'streaming'), None)
        if not leader or not candidate:
            return Response({'detail': _('There is no standby in sync to switch to (see the status below)')},
                            status=400)
        # scheduled a few seconds ahead: this server's services stop during the switch, so the answer
        # must go out first
        from datetime import datetime, timedelta, timezone as tz
        when = (datetime.now(tz.utc) + timedelta(seconds=5)).isoformat()
        try:
            r = requests.post(f'{PATRONI}/switchover',
                              json={'leader': leader, 'candidate': candidate, 'scheduled_at': when},
                              auth=('patroni', os.environ.get('HA_PATRONI_PASSWORD', '')), timeout=15)
        except Exception as e:
            return Response({'detail': str(e)[:200]}, status=503)
        if r.status_code not in (200, 202):
            return Response({'detail': _('Switchover refused: %s') % r.text[:200]}, status=400)
        return Response({'leader': candidate, 'detail': _('%s becomes the primary in a few seconds; XPAM moves there in about a minute')
                         % candidate})
