"""
XPAM: quicker asset management.

- bulk add   create many assets at once: a pasted list of addresses with one platform, nodes and account
- detect     sign in to network devices with their privileged account and set the right platform
             (FortiGate, Palo Alto, Cisco IOS/ASA/NX-OS, Juniper, Huawei, H3C)
- attention  the assets that have a problem (unreachable, no privileged account, failed account check,
             password never changed) and what to do about it
"""
import re
from concurrent.futures import ThreadPoolExecutor

from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _

from common.utils import get_logger

logger = get_logger(__name__)

MAX_BULK = 500
MAX_DETECT = 50
LIST_LIMIT = 20
OLD_PASSWORD_DAYS = 90
OK_STATES = ('ok', '-', 'na')

PLATFORM_OF_VENDOR = {
    'fortinet': 'FortiGate', 'paloalto': 'PaloAlto', 'cisco_ios': 'Cisco', 'cisco_asa': 'Cisco-ASA',
    'cisco_nxos': 'Cisco-NXOS', 'juniper': 'Juniper', 'huawei': 'Huawei', 'h3c': 'H3C',
}


class ToolError(Exception):
    pass


# ---------------------------------------------------------------- bulk add

def parse_lines(text):
    """'10.0.0.5' or 'web-01 10.0.0.5' or 'web-01,10.0.0.5' per line -> [(name, address)]."""
    rows = []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = [p for p in re.split(r'[\s,;]+', line) if p]
        if len(parts) == 1:
            rows.append((parts[0], parts[0]))
        else:
            rows.append((parts[0], parts[1]))
    if not rows:
        raise ToolError(_('Enter at least one address'))
    if len(rows) > MAX_BULK:
        raise ToolError(_('At most %s assets at a time') % MAX_BULK)
    return rows


def _serializer_class(category):
    from assets import serializers as s
    return {'host': s.HostSerializer, 'device': s.DeviceSerializer, 'database': s.DatabaseSerializer,
            'web': s.WebSerializer}.get(category)


def _license_room(n):
    """'' when `n` more active assets fit the licence, else the reason."""
    from django.conf import settings
    from orgs.utils import tmp_to_root_org
    from assets.models import Asset
    if not settings.XPACK_ENABLED:
        return ''
    try:
        from xpack.utils import get_current_license_info, get_license_asset_count
        if not get_current_license_info().get('is_valid', False):
            return _('License has expired. Creating assets is disabled. Please renew your license.')
        limit = get_license_asset_count()
    except ImportError:
        return ''
    with tmp_to_root_org():
        used = Asset.objects.filter(is_active=True).count()
    if used + n > limit:
        return _('The licence allows %(limit)s assets; %(used)s are in use, %(n)s more do not fit') % {
            'limit': limit, 'used': used, 'n': n}
    return ''


def bulk_add(request, platform_id, text, node_ids, account=None, db_name=''):
    """Create one asset per line. Returns {created: [...], failed: [{line, error}]}."""
    from common.utils import is_uuid
    from orgs.utils import current_org
    from assets.models import Platform, Node
    if current_org.is_root():
        raise ToolError(_('Choose an organization first: assets cannot be created in "All organizations"'))
    platform = Platform.objects.filter(id=platform_id).first() if str(platform_id or '').isdigit() else None
    if not platform:
        raise ToolError(_('Choose a platform'))
    cls = _serializer_class(platform.category)
    if not cls:
        raise ToolError(_('Bulk add supports servers, databases, network devices and websites'))
    rows = parse_lines(text)
    why = _license_room(len(rows))
    if why:
        raise ToolError(why)
    node_ids = [i for i in (node_ids or []) if is_uuid(i)]
    nodes = [str(n.id) for n in Node.objects.filter(id__in=node_ids)] or [str(Node.org_root().id)]
    accounts = []
    if account and account.get('username'):
        accounts = [{
            'name': account['username'], 'username': account['username'], 'secret_type': 'password',
            'secret': account.get('secret') or '', 'privileged': bool(account.get('privileged')),
        }]
    protocols = [{'name': p.name, 'port': p.port} for p in platform.protocols.all() if p.default or p.required or p.primary]
    created, failed = [], []
    for name, address in rows:
        data = {'name': name, 'address': address, 'platform': platform.id, 'nodes': nodes,
                'protocols': [dict(p) for p in protocols], 'accounts': [dict(a) for a in accounts]}
        if platform.category == 'database':
            data['db_name'] = db_name or ''
        serializer = cls(data=data, context={'request': request})
        if not serializer.is_valid():
            failed.append({'line': f'{name} {address}' if name != address else address,
                           'error': '; '.join(f'{k}: {v[0] if isinstance(v, list) else v}'
                                              for k, v in serializer.errors.items())[:300]})
            continue
        try:
            asset = serializer.save()
            created.append({'id': str(asset.id), 'name': asset.name, 'address': asset.address})
        except Exception as e:
            failed.append({'line': address, 'error': str(e)[:300]})
    return {'created': created, 'failed': failed}


# ---------------------------------------------------------------- detect the platform of network devices

def _detect_params(asset):
    """(SSH parameters, '') or (None, reason). Reads the database: runs in the request thread."""
    from accounts.jit.policy import admin_account
    if asset.platform.category != 'device':
        return None, _('Not a network device')
    if getattr(asset, 'zone_id', None) and asset.platform.gateway_enabled:
        return None, _('Devices reached through a gateway cannot be detected yet')
    account = admin_account(asset)
    if not account or account.secret_type != 'password':
        return None, _('Add a privileged account with a password on the device')
    port = asset.get_protocol_port('ssh') or 22
    return dict(host=asset.address, port=int(port), username=account.username, password=account.secret or '',
                secret=account.secret or '', allow_agent=False, use_keys=False, ssh_strict=False,
                system_host_keys=False, conn_timeout=20, auth_timeout=20, banner_timeout=20, timeout=60,
                fast_cli=False), ''


def _detect_vendor(params):
    """(platform name, '') or (None, reason). Network only (runs in a worker thread, no database)."""
    from libs.ansible.modules_utils.network_device import detect_vendor
    try:
        vendor = detect_vendor(params)
    except Exception as e:
        msg = str(e).replace(params['password'] or '\0', '***')
        return None, _('Cannot sign in to the device: %s') % msg[:200]
    name = PLATFORM_OF_VENDOR.get(vendor)
    if not name:
        return None, _('XPAM could not recognise the device')
    return name, ''


def detect_platforms(asset_ids):
    """Sign in to each device and move it to its platform. [{id, name, before, after, changed, error}]"""
    from common.utils import is_uuid
    from assets.models import Asset, Platform
    from assets.serializers.asset.common import AssetSerializer
    ids = [i for i in list(asset_ids)[:MAX_DETECT] if is_uuid(i)]
    assets = list(Asset.objects.filter(id__in=ids).select_related('platform'))
    if not assets:
        raise ToolError(_('Choose the devices to detect'))
    prepared = [_detect_params(a) for a in assets]  # database work here, in the request's organization
    todo = [p for p, _why in prepared if p]
    with ThreadPoolExecutor(max_workers=max(1, min(8, len(todo)))) as pool:
        detected = iter(list(pool.map(_detect_vendor, todo)))
    found = [next(detected) if p else (None, why) for p, why in prepared]
    results = []
    for asset, (name, error) in zip(assets, found):
        item = {'id': str(asset.id), 'name': asset.name, 'before': asset.platform.name, 'after': name or '',
                'changed': False, 'error': error}
        if name and name != asset.platform.name:
            platform = Platform.objects.filter(name=name, category='device').first()
            if not platform:
                item['error'] = _('The platform %s does not exist') % name
            else:
                old = asset.platform
                asset.platform = platform
                asset.save(update_fields=['platform'])
                AssetSerializer.sync_platform_protocols(asset, old)  # e.g. adds HTTP(s) for FortiGate
                item['changed'] = True
        results.append(item)
    return results


# ---------------------------------------------------------------- assets that need attention

def attention():
    """Problems of the current organization's assets, most important first."""
    from accounts.models import Account
    from assets.models import Asset
    managed = Q(platform__category__in=['host', 'device', 'database'])
    active = Asset.objects.filter(is_active=True)
    groups = []

    def add(key, title, fix, qs, count=None):
        count = qs.count() if count is None else count
        if count:
            groups.append({'key': key, 'title': title, 'fix': fix, 'count': count,
                           'assets': [{'id': str(a.id), 'name': a.name, 'address': a.address}
                                      for a in qs.order_by('name')[:LIST_LIMIT]]})

    add('unreachable', _('Unreachable'),
        _('Check the address, the port and the firewall between XPAM and the asset, then "Test" the asset.'),
        active.exclude(connectivity__in=OK_STATES))

    with_privileged = Account.objects.filter(is_active=True, privileged=True).exclude(source='jit') \
        .values('asset_id')
    add('no_privileged', _('No privileged account'),
        _('Add the admin/root account and turn on "Privileged": account push, password changes, account '
          'discovery and just-in-time accounts sign in with it.'),
        active.filter(managed).exclude(id__in=with_privileged))

    bad = Account.objects.filter(is_active=True).exclude(source='jit').exclude(connectivity__in=OK_STATES)
    add('account_failed', _('Account check failed'),
        _('The stored password or key no longer works: update it, or let XPAM change it ("Change secret").'),
        active.filter(id__in=bad.values('asset_id')))

    old = timezone.now() - timezone.timedelta(days=OLD_PASSWORD_DAYS)
    stale = Account.objects.filter(is_active=True, privileged=True, secret_type='password').exclude(source='jit') \
        .filter(Q(date_change_secret__isnull=True, date_created__lt=old) | Q(date_change_secret__lt=old))
    add('old_password', _('Admin password not changed for %s days') % OLD_PASSWORD_DAYS,
        _('Create an account change plan (Accounts → Automations → Change secret) so XPAM rotates it.'),
        active.filter(managed, id__in=stale.values('asset_id')))

    return {'total': active.count(), 'groups': groups}
