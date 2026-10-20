"""
XPAM 5.1.9: network devices get account push, change secret, removal and discovery with their role.

Adds the FortiGate, PaloAlto, Cisco-ASA, Cisco-NXOS and Juniper platforms (only when no platform of
that name exists) and moves the built-in Cisco, Huawei and H3C platforms to the network methods.
"""
from django.db import migrations

from assets.const import AllTypes

NETWORK_METHODS = {
    'push_account': 'push_account_network',
    'change_secret': 'change_secret_network',
    'remove_account': 'remove_account_network',
    'gather_accounts': 'gather_accounts_network',
}


def automation(vendor, su=False):
    data = {
        'ansible_enabled': True,
        'ansible_config': {'ansible_connection': 'local', 'first_connect_delay': 0.5},
        'ping_enabled': True, 'ping_method': 'ping_by_ssh', 'ping_params': {},
        'gather_facts_enabled': False, 'gather_facts_method': None, 'gather_facts_params': {},
        'verify_account_enabled': True, 'verify_account_method': 'verify_account_by_ssh',
        'verify_account_params': {},
    }
    for kind, method in NETWORK_METHODS.items():
        params = {'vendor': vendor}
        if kind == 'push_account':
            params.update(role='read_only', custom_role='')
        data.update({f'{kind}_enabled': True, f'{kind}_method': method, f'{kind}_params': {method: params}})
    return data


def platform(name, tp, vendor, su_method=None):
    return {
        'created_by': 'system', 'updated_by': 'system', 'comment': '', 'name': name, 'category': 'device',
        'type': tp, 'meta': {}, 'internal': True, 'charset': 'utf-8', 'gateway_enabled': True,
        'ds_enabled': True, 'su_enabled': bool(su_method), 'su_method': su_method, 'custom_fields': [],
        'automation': automation(vendor),
        'protocols': [
            {'name': 'ssh', 'port': 22, 'primary': True, 'required': True, 'default': True, 'public': True,
             'setting': {'sftp_home': '/tmp', 'sftp_enabled': False}},
            {'name': 'telnet', 'port': 23, 'primary': False, 'required': False, 'default': False, 'public': True,
             'setting': {}},
        ],
    }


NEW_PLATFORMS = [
    platform('FortiGate', 'firewall', 'fortinet'),
    platform('PaloAlto', 'firewall', 'paloalto'),
    platform('Cisco-ASA', 'firewall', 'cisco_asa', su_method='enable'),
    platform('Cisco-NXOS', 'switch', 'cisco_nxos'),
    platform('Juniper', 'router', 'juniper'),
]
EXISTING = {'Cisco': 'cisco_ios', 'Huawei': 'huawei', 'H3C': 'h3c'}


def forwards(apps, schema_editor):
    platform_model = apps.get_model('assets', 'Platform')
    automation_model = apps.get_model('assets', 'PlatformAutomation')
    for data in NEW_PLATFORMS:
        if platform_model.objects.filter(name=data['name']).exists():
            continue  # never overwrite a platform the administrator made
        AllTypes.create_or_update_by_platform_data(dict(data), platform_cls=platform_model,
                                                   automation_cls=automation_model)
    for name, vendor in EXISTING.items():
        p = platform_model.objects.filter(name=name, internal=True, category='device').first()
        try:
            auto = p.automation if p else None
        except Exception:
            auto = None
        if not auto:
            continue
        for kind, method in NETWORK_METHODS.items():
            current = getattr(auto, f'{kind}_method')
            params = getattr(auto, f'{kind}_params') or {}
            # keep an "SSH custom commands" method the administrator has filled in
            if current == f'{kind}_by_ssh' and (params.get(current) or {}).get('commands'):
                continue
            extra = {'role': 'read_only', 'custom_role': ''} if kind == 'push_account' else {}
            setattr(auto, f'{kind}_enabled', True)
            setattr(auto, f'{kind}_method', method)
            setattr(auto, f'{kind}_params', {method: dict(vendor=vendor, **extra)})
        auto.save()


class Migration(migrations.Migration):
    dependencies = [
        ('assets', '0029_add_virtual_app_host_platform'),
    ]

    operations = [
        migrations.RunPython(forwards, reverse_code=migrations.RunPython.noop),
    ]
