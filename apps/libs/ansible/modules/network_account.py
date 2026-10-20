#!/usr/bin/python

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = '''
---
module: network_account
short_description: Local accounts of firewalls, routers and switches (XPAM)
description:
    - Creates, changes, removes and lists local accounts on network devices over SSH, with their role.
    - FortiGate, Palo Alto, Cisco IOS/IOS-XE, Cisco ASA, Cisco NX-OS, Juniper, Huawei and H3C.
options:
  action:
    description: push (create or update), change (password), remove, gather (list accounts).
    choices: [push, change, remove, gather]
    required: true
    type: str
  vendor:
    description: Vendor of the device; auto recognises it.
    default: auto
    type: str
  name:
    description: The account to push, change or remove.
    type: str
  password:
    description: The account's new password.
    type: str
  role:
    description: read_only, operator, admin or custom.
    default: read_only
    type: str
  custom_role:
    description: Vendor role for the custom role (FortiGate admin profile, PAN-OS role profile, privilege level...).
    type: str
'''

EXAMPLES = '''
- name: Push a read-only account to a FortiGate
  network_account:
    login_host: 10.0.0.1
    login_port: 22
    login_user: admin
    login_password: secret
    action: push
    vendor: fortinet
    name: audit
    password: Strong-pass1
    role: read_only
'''

RETURN = '''
info:
    description: For gather, the accounts found on the device with their role.
    returned: gather
    type: dict
'''

from ansible.module_utils.basic import AnsibleModule

from libs.ansible.modules_utils.network_device import (
    DeviceError, ROLES, gateway_from_args, redact, session, vendor_from_name
)


def credentials(p):
    """The SSH credentials and the enable/super password, as XPAM's inventory gives them."""
    if p['become'] and p['become_user']:
        # signed in with the "su from" account, the privileged account's secret enables
        return (p['become_user'], p['become_password'] or '', p['become_private_key_path'],
                p['login_password'] or '')
    key = p['login_private_key_path'] if p['login_secret_type'] == 'ssh_key' else None
    return p['login_user'], p['login_password'] or '', key, p['enable_password'] or p['login_password'] or ''


def main():
    argument_spec = dict(
        login_host=dict(type='str', required=True),
        login_port=dict(type='int', default=22),
        login_user=dict(type='str', required=True),
        login_password=dict(type='str', default='', no_log=True),
        login_secret_type=dict(type='str', default='password'),
        login_private_key_path=dict(type='str', default=None, no_log=True),
        become=dict(type='bool', default=False),
        become_method=dict(type='str', default=''),
        become_user=dict(type='str', default=''),
        become_password=dict(type='str', default='', no_log=True),
        become_private_key_path=dict(type='str', default=None, no_log=True),
        enable_password=dict(type='str', default='', no_log=True),
        gateway_args=dict(type='str', default='', no_log=True),
        action=dict(type='str', required=True, choices=['push', 'change', 'remove', 'gather']),
        vendor=dict(type='str', default='auto'),
        platform=dict(type='str', default=''),
        name=dict(type='str', default=''),
        password=dict(type='str', default='', no_log=True),
        old_password=dict(type='str', default='', no_log=True),
        role=dict(type='str', default='read_only'),
        custom_role=dict(type='str', default=''),
        commit=dict(type='str', default='partial'),
        vdom=dict(type='str', default='root'),
        timeout=dict(type='int', default=30),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=False)
    p = module.params
    user, password, key, enable = credentials(p)
    vendor = p['vendor'] if p['vendor'] not in ('', 'auto') else (vendor_from_name(p['platform']) or 'auto')
    role = p['role'] if p['role'] in ROLES else 'read_only'
    secrets = (password, enable, p['password'], p['old_password'])
    try:
        gateway = gateway_from_args(p['gateway_args'])
        with session(vendor, p['login_host'], p['login_port'], user, password, key_file=key, enable_password=enable,
                     gateway=gateway, timeout=p['timeout'],
                     options={'commit': p['commit'], 'vdom': p['vdom']}) as dev:
            if p['action'] == 'gather':
                info = {}
                for u in dev.list_users():
                    # the role is reported as "groups": discovery flags a changed role as a risk
                    info[u['username']] = {'detail': {
                        'groups': u.get('raw_role') or '', 'vendor': dev.vendor, 'role': u.get('role'),
                        'admin': u.get('role') == 'admin'}}
                module.exit_json(changed=False, vendor=dev.vendor, ansible_facts={'info': info})
            if p['action'] == 'push':
                result = dev.push(p['name'], p['password'], role, p['custom_role'])
                module.exit_json(changed=True, vendor=dev.vendor, result=result, name=p['name'])
            if p['action'] == 'change':
                dev.change(p['name'], p['password'], p['old_password'])
                module.exit_json(changed=True, vendor=dev.vendor, name=p['name'])
            removed = dev.remove(p['name'])
            module.exit_json(changed=removed, vendor=dev.vendor, name=p['name'],
                             msg='' if removed else 'The account was not on the device')
    except DeviceError as e:
        module.fail_json(msg=redact(e, *secrets))
    except Exception as e:
        module.fail_json(msg=redact('%s: %s' % (e.__class__.__name__, e), *secrets)[:1000])


if __name__ == '__main__':
    main()
