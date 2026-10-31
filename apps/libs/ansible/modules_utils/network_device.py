"""
XPAM network device accounts.

Creates, changes, removes and lists the local accounts of firewalls, routers and switches over SSH
(netmiko), with the account's role (read only / operator / administrator / custom). The same code
serves account push, change secret, account removal, account discovery and just-in-time accounts.

Supported: FortiGate (FortiOS), Palo Alto (PAN-OS), Cisco IOS / IOS-XE, Cisco ASA, Cisco NX-OS,
Juniper (Junos), Huawei (VRP) and H3C (Comware). 'auto' recognises the vendor from the device.
"""
import contextlib
import re

ROLES = ('read_only', 'operator', 'admin', 'custom')
ROLE_LABELS = {'read_only': 'Read only', 'operator': 'Operator', 'admin': 'Administrator', 'custom': 'Custom'}

# characters that device command lines treat specially (help, quoting, comments)
CONFIRM = r'\[confirm\]|\[[Yy]/[Nn]\]|\(y/n\)|continue\?\s*$'
UNSAFE_PASSWORD_CHARS = set(' \t\r\n?"\'\\`')
USERNAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._@-]{0,62}$')


class DeviceError(Exception):
    pass


ROLE_NAME_RE = re.compile(r'[A-Za-z0-9_.@-]{1,63}')


def check_name(value, what):
    """Role / profile / VDOM names go into device commands: plain names only (no spaces, quotes, newlines)."""
    if not ROLE_NAME_RE.fullmatch(str(value or '')):
        raise DeviceError('The %s "%s" is not valid (letters, digits, . _ @ - only)' % (what, value))
    return value


def check_username(username):
    if not USERNAME_RE.fullmatch(username or ''):
        raise DeviceError('The user name "%s" is not valid on network devices (letters, digits, . _ @ -)' % username)


def check_password(password):
    if not password:
        raise DeviceError('The password is empty')
    bad = sorted({c for c in password if c in UNSAFE_PASSWORD_CHARS})
    if bad:
        shown = ' '.join('space' if c == ' ' else repr(c) for c in bad)
        raise DeviceError('The password contains characters network devices do not accept: %s' % shown)


def redact(text, *secrets):
    text = str(text or '')
    for secret in secrets:
        if secret:
            text = text.replace(secret, '******')
    return text


class Driver:
    vendor = ''
    label = ''
    netmiko_type = ''
    error_patterns = (r'% ?Invalid input', r'% ?Incomplete command', r'% ?Ambiguous command', r'^\s*ERROR:',
                      r'^\s*Error:')
    needs_save = False
    config_enter, config_exit = 'configure terminal', 'end'

    def __init__(self, conn, options=None):
        self.conn = conn
        self.options = options or {}
        self.login_user = self.options.get('login_user', '')

    # ---- helpers
    def check_errors(self, output, *secrets):
        for pattern in self.error_patterns:
            match = re.search(pattern, output or '', flags=re.M | re.I)
            if match:
                line = (output[match.start():].splitlines() or [''])[0]
                raise DeviceError('The device refused a command: %s' % redact(line.strip(), *secrets)[:300])

    def send(self, command, read_timeout=60):
        """One command, read until the prompt is back; answers yes/confirm questions."""
        pattern = r'(?:%s)|(?:%s)' % (re.escape(self.conn.base_prompt), CONFIRM)
        out = self.conn.send_command(command, expect_string=pattern, strip_prompt=False, strip_command=False,
                                     read_timeout=read_timeout)
        for _ in range(3):
            tail = out.rstrip().splitlines()[-1] if out.strip() else ''
            if not re.search(CONFIRM, tail, re.I):
                break
            answer = 'y' if re.search(r'[Yy]/[Nn]|y/n|continue', tail) else ''
            out += self.conn.send_command(answer, expect_string=pattern, strip_prompt=False, strip_command=False,
                                          read_timeout=read_timeout, cmd_verify=False)
        return out

    def show(self, command, read_timeout=60):
        return self.conn.send_command(command, read_timeout=read_timeout)

    def configure(self, commands, *secrets):
        # entered directly: netmiko's own configuration-mode checks wait seconds on every call
        output = self.send(self.config_enter)
        try:
            for command in commands:
                output += self.send(command)
        finally:
            output += self.send(self.config_exit)
        self.check_errors(output, *secrets)
        return output

    def elevate(self, password):
        """Enter the privileged mode (enable / super) when the device needs it."""
        try:
            if self.conn.check_enable_mode():
                return
        except Exception:
            return
        if not password:
            return
        self.conn.secret = password
        self.conn.enable()

    def role_of(self, raw):
        return 'custom'

    # ---- account operations (vendor specific)
    def list_users(self):
        raise NotImplementedError

    def create_user(self, username, password, role, custom_role=''):
        raise NotImplementedError

    def set_password(self, username, password, old_password=''):
        raise NotImplementedError

    def delete_user(self, username):
        raise NotImplementedError

    def save(self):
        if self.needs_save:
            out = self.conn.save_config()
            self.check_errors(out)

    # ---- generic
    def user(self, username):
        for u in self.list_users():
            if u['username'] == username:
                return u
        return None

    def push(self, username, password, role, custom_role='', update_role=False):
        """
        Create the account with its role, or update the password of an existing one. The role of an
        existing account is only changed when asked (pushing a discovered admin must not demote it).
        """
        check_username(username)
        check_password(password)
        if role == 'custom':
            check_name(custom_role, 'custom role')
        existing = self.user(username)
        if existing and update_role:
            self.update_user(username, password, role, custom_role, existing)
            changed = 'updated'
        elif existing:
            self.set_password(username, password)
            changed = 'updated'
        else:
            self.create_user(username, password, role, custom_role)
            changed = 'created'
        self.save()
        return changed

    def update_user(self, username, password, role, custom_role, existing):
        # most CLIs set the role and the password with the same command as when creating
        self.create_user(username, password, role, custom_role)

    def change(self, username, password, old_password=''):
        check_username(username)
        check_password(password)
        if old_password:
            check_password(old_password)  # (FortiOS takes it on the command line too)
        if not self.user(username):
            raise DeviceError('The account %s does not exist on the device' % username)
        self.set_password(username, password, old_password)
        self.save()

    def remove(self, username):
        check_username(username)
        if username == self.login_user:
            raise DeviceError('XPAM will not remove the account it signs in with')
        if not self.user(username):
            return False
        self.delete_user(username)
        self.save()
        return True


# ------------------------------------------------------------------ FortiGate

class FortiGate(Driver):
    vendor, label, netmiko_type = 'fortinet', 'FortiGate (FortiOS)', 'fortinet'
    error_patterns = (r'Command fail\. Return code', r'command parse error', r'value parse error',
                      r'node_check_object fail', r'entry not found', r'Unknown action')
    READ_ONLY_PROFILE = 'xpam_read_only'
    READ_GROUPS = ('secfabgrp', 'ftviewgrp', 'authgrp', 'sysgrp', 'netgrp', 'loggrp', 'fwgrp', 'vpngrp',
                   'utmgrp', 'wanoptgrp', 'wifi')

    def _global(self, commands):
        vdoms = getattr(self.conn, '_vdoms', False)
        return (['config global'] + commands + ['end']) if vdoms else commands

    def run(self, commands, *secrets):
        output = ''
        for command in self._global(commands):
            output += self.send(command)
        self.check_errors(output, *secrets)
        return output

    def configure(self, commands, *secrets):  # FortiOS has no separate configuration mode
        return self.run(commands, *secrets)

    def elevate(self, password):
        return

    def show_admins(self):
        if getattr(self.conn, '_vdoms', False):
            out = self.send('config global')
            out = self.show('show system admin')
            self.send('end')
            return out
        return self.show('show system admin')

    def list_users(self):
        users, current = [], None
        for line in self.show_admins().splitlines():
            m = re.match(r'\s*edit "?([^"]+?)"?\s*$', line)
            if m:
                current = {'username': m.group(1), 'raw_role': '', 'vdom': ''}
                users.append(current)
                continue
            if current is None:
                continue
            m = re.match(r'\s*set accprofile "?([^"]+?)"?\s*$', line)
            if m:
                current['raw_role'] = m.group(1)
            m = re.match(r'\s*set vdom (.+)$', line)
            if m:
                current['vdom'] = m.group(1).replace('"', '').strip()
            if re.match(r'\s*next\s*$', line):
                current = None
        for u in users:
            u['role'] = self.role_of(u['raw_role'])
        return users

    def role_of(self, raw):
        if raw == 'super_admin':
            return 'admin'
        if raw == 'prof_admin':
            return 'operator'
        if raw == self.READ_ONLY_PROFILE or 'read' in raw.lower():
            return 'read_only'
        return 'custom'

    def profile(self, role, custom_role):
        if role == 'admin':
            return 'super_admin'
        if role == 'operator':
            return 'prof_admin'
        if role == 'custom':
            if not custom_role:
                raise DeviceError('Enter the FortiGate admin profile for the custom role')
            return custom_role
        self.ensure_read_only_profile()
        return self.READ_ONLY_PROFILE

    def ensure_read_only_profile(self):
        out = self.run(['show system accprofile'])
        if 'edit "%s"' % self.READ_ONLY_PROFILE in out:
            return
        commands = ['config system accprofile', 'edit "%s"' % self.READ_ONLY_PROFILE]
        commands += ['set %s read' % g for g in self.READ_GROUPS] + ['next', 'end']
        out = ''
        for command in self._global(commands):
            out += self.send(command)  # (some groups do not exist on every FortiOS version: ignored)

    def _vdom_line(self, profile):
        if getattr(self.conn, '_vdoms', False) and profile != 'super_admin':
            return ['set vdom "%s"' % check_name(self.options.get('vdom') or 'root', 'VDOM')]
        return []

    def create_user(self, username, password, role, custom_role=''):
        profile = self.profile(role, custom_role)
        self.run(['config system admin', 'edit "%s"' % username, 'set accprofile "%s"' % profile]
                 + self._vdom_line(profile) + ['set password "%s"' % password, 'next', 'end'], password)

    def set_password(self, username, password, old_password=''):
        line = 'set password "%s"' % password
        if username == self.login_user and old_password:
            line += ' "%s"' % old_password  # FortiOS asks for the current password of the signed-in admin
        self.run(['config system admin', 'edit "%s"' % username, line, 'next', 'end'], password, old_password)

    def update_user(self, username, password, role, custom_role, existing):
        profile = self.profile(role, custom_role)
        self.run(['config system admin', 'edit "%s"' % username, 'set accprofile "%s"' % profile]
                 + self._vdom_line(profile) + ['next', 'end'])
        self.set_password(username, password)

    def delete_user(self, username):
        self.run(['config system admin', 'delete "%s"' % username, 'end'])


# ------------------------------------------------------------------ Palo Alto

class PaloAlto(Driver):
    vendor, label, netmiko_type = 'paloalto', 'Palo Alto (PAN-OS)', 'paloalto_panos'
    error_patterns = (r'Invalid syntax', r'Unknown command', r'^\s*Server error', r'^\s*Validation Error',
                      r'is not a valid', r'Commit failed')

    def elevate(self, password):
        return

    config_enter, config_exit = 'configure', 'exit'

    def configure(self, commands, *secrets):
        try:
            return super().configure(commands, *secrets)
        except Exception:
            # leave nothing of XPAM's in the candidate configuration for the next admin's commit
            try:
                self.send('configure')
                self.send('revert config partial admin %s' % check_name(self.login_user, 'admin name'))
                self.send('exit')
            except Exception:
                pass
            raise

    def phash(self, password):
        out = self.show('request password-hash password "%s"' % password)
        m = re.search(r'(\$\d\$\S+)', out)
        if not m:
            raise DeviceError('The firewall did not return a password hash: %s' % redact(out, password)[:200])
        return m.group(1)

    def list_users(self):
        self.send('set cli config-output-format set')
        try:
            out = self.configure(['show mgt-config users'])
        finally:
            self.send('set cli config-output-format default')
        users = {}
        for line in out.splitlines():
            m = re.match(r'\s*set mgt-config users (\S+)(?: (.*))?$', line)
            if not m:
                continue
            u = users.setdefault(m.group(1), {'username': m.group(1), 'raw_role': ''})
            rest = m.group(2) or ''
            r = re.match(r'permissions role-based (\S+)(?: (.*))?$', rest)
            if r:
                u['raw_role'] = r.group(1) if r.group(1) != 'custom' else 'custom ' + (r.group(2) or '').replace(
                    'profile ', '')
        result = list(users.values())
        for u in result:
            u['role'] = self.role_of(u['raw_role'])
        return result

    def role_of(self, raw):
        if raw == 'superuser':
            return 'admin'
        if raw in ('superreader', 'devicereader', 'vsysreader'):
            return 'read_only'
        if raw in ('deviceadmin', 'vsysadmin'):
            return 'operator'
        return 'custom'

    def role_command(self, username, role, custom_role):
        base = 'set mgt-config users %s permissions role-based ' % username
        if role == 'admin':
            return base + 'superuser yes'
        if role == 'read_only':
            return base + 'superreader yes'
        if role == 'operator':
            return base + 'deviceadmin localhost.localdomain'
        if not custom_role:
            raise DeviceError('Enter the Palo Alto admin role profile for the custom role')
        return base + 'custom profile %s' % custom_role

    def commit(self):
        if (self.options.get('commit') or 'partial') == 'full':
            command = 'commit'
        else:
            # only XPAM's own change: other administrators' pending changes are not committed
            command = 'commit partial admin %s' % check_name(self.login_user, 'admin name')
        self.send('configure')
        try:
            out = self.conn.send_command(command, expect_string=r'100%|[Ff]ail|[Ee]rror|Invalid|successfully',
                                         read_timeout=600, strip_prompt=False, strip_command=False)
            if 'successfully' not in out.lower() and '100%' in out:
                out += self.conn.read_until_pattern(pattern=r'successfully|[Ff]ail', read_timeout=120)
        finally:
            self.send('exit')
        if 'configuration committed successfully' not in out.lower():
            raise DeviceError('The commit failed: %s' % out.strip()[-300:])

    def create_user(self, username, password, role, custom_role=''):
        phash = self.phash(password)
        self.configure(['set mgt-config users %s phash "%s"' % (username, phash),
                        self.role_command(username, role, custom_role)])
        self.commit()

    def update_user(self, username, password, role, custom_role, existing):
        phash = self.phash(password)
        self.configure(['delete mgt-config users %s permissions' % username,
                        'set mgt-config users %s phash "%s"' % (username, phash),
                        self.role_command(username, role, custom_role)])
        self.commit()

    def set_password(self, username, password, old_password=''):
        self.configure(['set mgt-config users %s phash "%s"' % (username, self.phash(password))])
        self.commit()

    def delete_user(self, username):
        self.configure(['delete mgt-config users %s' % username])
        self.commit()


# ------------------------------------------------------------------ Cisco

class CiscoIOS(Driver):
    vendor, label, netmiko_type = 'cisco_ios', 'Cisco IOS / IOS-XE', 'cisco_ios'
    needs_save = True
    PRIVILEGE = {'read_only': 1, 'operator': 7, 'admin': 15}

    def privilege(self, role, custom_role):
        if role == 'custom':
            if not str(custom_role).isdigit() or not 0 <= int(custom_role) <= 15:
                raise DeviceError('Enter a privilege level from 0 to 15 for the custom role')
            return int(custom_role)
        return self.PRIVILEGE[role]

    def role_of(self, raw):
        level = int(raw) if str(raw).isdigit() else 1
        for role, value in self.PRIVILEGE.items():
            if value == level:
                return role
        return 'custom'

    def list_users(self):
        users = []
        for line in self.show('show running-config | include ^username').splitlines():
            m = re.match(r'username (\S+)(?:.*?\bprivilege (\d+))?', line.strip())
            if m:
                level = m.group(2) or '1'
                users.append({'username': m.group(1), 'raw_role': 'privilege %s' % level,
                              'role': self.role_of(level)})
        return users

    def create_user(self, username, password, role, custom_role=''):
        level = self.privilege(role, custom_role)
        self.configure(['username %s privilege %d secret %s' % (username, level, password)], password)

    def set_password(self, username, password, old_password=''):
        u = self.user(username) or {}
        level = re.sub(r'\D', '', u.get('raw_role', '')) or '1'
        self.configure(['username %s privilege %s secret %s' % (username, level, password)], password)

    def delete_user(self, username):
        self.configure(['no username %s' % username])


class CiscoASA(CiscoIOS):
    vendor, label, netmiko_type = 'cisco_asa', 'Cisco ASA', 'cisco_asa'
    PRIVILEGE = {'read_only': 5, 'operator': 10, 'admin': 15}

    def list_users(self):
        users = []
        for line in self.show('show running-config username').splitlines():
            m = re.match(r'username (\S+)(?:.*?\bprivilege (\d+))?', line.strip())
            if m and not line.strip().startswith('username %s attributes' % m.group(1)):
                level = m.group(2) or '2'
                users.append({'username': m.group(1), 'raw_role': 'privilege %s' % level,
                              'role': self.role_of(level)})
        return users

    def create_user(self, username, password, role, custom_role=''):
        level = self.privilege(role, custom_role)
        self.configure(['username %s password %s privilege %d' % (username, password, level)], password)

    def set_password(self, username, password, old_password=''):
        u = self.user(username) or {}
        level = re.sub(r'\D', '', u.get('raw_role', '')) or '2'
        self.configure(['username %s password %s privilege %s' % (username, password, level)], password)


class CiscoNXOS(Driver):
    vendor, label, netmiko_type = 'cisco_nxos', 'Cisco NX-OS', 'cisco_nxos'
    needs_save = True
    ROLE = {'read_only': 'network-operator', 'operator': 'network-operator', 'admin': 'network-admin'}

    def role_of(self, raw):
        roles = [r.strip() for r in raw.split(',') if r.strip()]
        if 'network-admin' in roles:
            return 'admin'
        if roles and set(roles) <= {'network-operator'}:
            return 'read_only'
        return 'custom'

    def list_users(self):
        users = {}
        for line in self.show('show running-config | include ^username').splitlines():
            m = re.match(r'username (\S+)(?:.*?\brole (\S+))?', line.strip())
            if m:
                u = users.setdefault(m.group(1), {'username': m.group(1), 'roles': []})
                if m.group(2) and m.group(2) not in u['roles']:
                    u['roles'].append(m.group(2))
        result = []
        for u in users.values():
            raw = ', '.join(u.pop('roles'))
            result.append(dict(u, raw_role=raw, role=self.role_of(raw)))
        return result

    def update_user(self, username, password, role, custom_role, existing):
        wanted = self.nx_role(role, custom_role)
        old = [r.strip() for r in existing.get('raw_role', '').split(',') if r.strip() and r.strip() != wanted]
        self.configure(['username %s password %s role %s' % (username, password, wanted)]
                       + ['no username %s role %s' % (username, r) for r in old], password)

    def nx_role(self, role, custom_role):
        if role == 'custom':
            if not custom_role:
                raise DeviceError('Enter the NX-OS role name for the custom role')
            return custom_role
        return self.ROLE[role]

    @staticmethod
    def check_nx_password(password):
        # (NX-OS runs the commands of one line separated by ;)
        if ';' in password:
            raise DeviceError("The password contains characters network devices do not accept: ';'")

    def create_user(self, username, password, role, custom_role=''):
        self.check_nx_password(password)
        self.configure(['username %s password %s role %s' % (username, password, self.nx_role(role, custom_role))],
                       password)

    def set_password(self, username, password, old_password=''):
        self.check_nx_password(password)
        self.configure(['username %s password %s' % (username, password)], password)

    def delete_user(self, username):
        self.configure(['no username %s' % username])

    def save(self):
        out = self.send('copy running-config startup-config', read_timeout=120)
        self.check_errors(out)


# ------------------------------------------------------------------ Juniper

class Juniper(Driver):
    vendor, label, netmiko_type = 'juniper', 'Juniper (Junos)', 'juniper_junos'
    error_patterns = (r'^\s*error:', r'syntax error', r'unknown command', r'commit failed')
    CLASS = {'read_only': 'read-only', 'operator': 'operator', 'admin': 'super-user'}

    def elevate(self, password):
        return

    def role_of(self, raw):
        return {'super-user': 'admin', 'operator': 'operator', 'read-only': 'read_only'}.get(raw, 'custom')

    def list_users(self):
        users = {}
        for line in self.show('show configuration system login | display set').splitlines():
            m = re.match(r'set system login user (\S+)(?: (.*))?$', line.strip())
            if m:
                u = users.setdefault(m.group(1), {'username': m.group(1), 'raw_role': ''})
                c = re.match(r'class (\S+)', m.group(2) or '')
                if c:
                    u['raw_role'] = c.group(1)
        result = list(users.values())
        for u in result:
            u['role'] = self.role_of(u['raw_role'])
        return result

    def junos_class(self, role, custom_role):
        if role == 'custom':
            if not custom_role:
                raise DeviceError('Enter the Junos login class for the custom role')
            return custom_role
        return self.CLASS[role]

    def _password_commands(self, username, password):
        self.conn.write_channel('set system login user %s authentication plain-text-password\n' % username)
        out = self.conn.read_until_pattern(pattern=r'[Pp]assword:', read_timeout=20)
        self.conn.write_channel(password + '\n')
        out += self.conn.read_until_pattern(pattern=r'[Pp]assword:', read_timeout=20)
        self.conn.write_channel(password + '\n')
        out += self.conn.read_until_pattern(pattern=r'#', read_timeout=20)
        return out

    def _commit(self, commands, username='', password=''):
        # "configure private": XPAM's own candidate; other administrators' pending edits are neither
        # committed by "commit and-quit" nor thrown away by "rollback 0"
        self.conn.config_mode(config_command='configure private')
        out = ''
        try:
            for command in commands:
                out += self.send(command)
            if password:
                out += self._password_commands(username, password)
            self.check_errors(out, password)
            out = self.conn.send_command('commit and-quit', read_timeout=300, strip_prompt=False,
                                         expect_string=re.escape(self.conn.base_prompt) + r'>')
        except Exception:
            try:
                self.send('rollback 0')
                self.conn.exit_config_mode()
            except Exception:
                pass
            raise
        if 'commit complete' not in out:
            raise DeviceError('The commit failed: %s' % redact(out, password).strip()[-300:])

    def create_user(self, username, password, role, custom_role=''):
        self._commit(['set system login user %s class %s' % (username, self.junos_class(role, custom_role))],
                     username, password)

    def set_password(self, username, password, old_password=''):
        self._commit([], username, password)

    def delete_user(self, username):
        self._commit(['delete system login user %s' % username])


# ------------------------------------------------------------------ Huawei / H3C

class Huawei(Driver):
    vendor, label, netmiko_type = 'huawei', 'Huawei (VRP)', 'huawei'
    error_patterns = (r'^\s*Error:', r'Unrecognized command', r'Incomplete command', r'Wrong parameter')
    needs_save = True
    config_enter, config_exit = 'system-view', 'return'
    LEVEL = {'read_only': 1, 'operator': 2, 'admin': 15}

    def elevate(self, password):
        if not password:
            return
        prompt = self.conn.find_prompt()
        if prompt.startswith('<'):
            out = self.conn.send_command_timing('super', strip_prompt=False, strip_command=False)
            if 'assword' in out:
                self.conn.send_command_timing(password, strip_prompt=False, strip_command=False)

    def role_of(self, raw):
        level = int(raw) if str(raw).isdigit() else 0
        if level >= 3:
            return 'admin'
        return {1: 'read_only', 2: 'operator'}.get(level, 'custom')

    def level(self, role, custom_role):
        if role == 'custom':
            if not str(custom_role).isdigit() or not 0 <= int(custom_role) <= 15:
                raise DeviceError('Enter a privilege level from 0 to 15 for the custom role')
            return int(custom_role)
        return self.LEVEL[role]

    def list_users(self):
        users = {}
        out = self.show('display current-configuration configuration aaa')
        for line in out.splitlines():
            m = re.match(r'\s*local-user (\S+) (.*)$', line)
            if m:
                u = users.setdefault(m.group(1), {'username': m.group(1), 'raw_role': ''})
                lv = re.match(r'privilege level (\d+)', m.group(2))
                if lv:
                    u['raw_role'] = lv.group(1)
        result = list(users.values())
        for u in result:
            u['role'] = self.role_of(u['raw_role'])
            u['raw_role'] = 'level %s' % (u['raw_role'] or '0')
        return result

    def create_user(self, username, password, role, custom_role=''):
        level = self.level(role, custom_role)
        self.configure(['aaa', 'local-user %s password irreversible-cipher %s' % (username, password),
                        'local-user %s privilege level %d' % (username, level),
                        'local-user %s service-type ssh terminal' % username, 'quit',
                        'ssh user %s authentication-type password' % username,
                        'ssh user %s service-type stelnet' % username], password)

    def set_password(self, username, password, old_password=''):
        self.configure(['aaa', 'local-user %s password irreversible-cipher %s' % (username, password), 'quit'],
                       password)

    def delete_user(self, username):
        self.configure(['aaa', 'undo local-user %s' % username, 'quit', 'undo ssh user %s' % username])

    def save(self):
        out = self.send('save', read_timeout=120)
        self.check_errors(out)


class H3C(Huawei):
    vendor, label, netmiko_type = 'h3c', 'H3C (Comware)', 'hp_comware'
    ROLE = {'read_only': 'network-operator', 'operator': 'level-10', 'admin': 'network-admin'}

    def elevate(self, password):
        if not password:
            return
        out = self.conn.send_command_timing('super', strip_prompt=False, strip_command=False)
        if 'assword' in out:
            self.conn.send_command_timing(password, strip_prompt=False, strip_command=False)

    def role_of(self, raw):
        roles = [r.strip() for r in raw.split(',') if r.strip()]
        if 'network-admin' in roles or 'level-15' in roles:
            return 'admin'
        if any(r.startswith('level-') for r in roles):
            return 'operator'
        if roles and set(roles) <= {'network-operator'}:
            return 'read_only'
        return 'custom'

    def list_users(self):
        users, current = [], None
        for line in self.show('display local-user').splitlines():
            m = re.match(r'\s*Device management user (\S+?):?\s*$', line)
            if m:
                current = {'username': m.group(1), 'raw_role': ''}
                users.append(current)
                continue
            m = re.match(r'\s*User role list:\s*(.*)$', line)
            if m and current is not None:
                current['raw_role'] = m.group(1).strip()
        for u in users:
            u['role'] = self.role_of(u['raw_role'])
        return users

    def h3c_role(self, role, custom_role):
        if role == 'custom':
            if not custom_role:
                raise DeviceError('Enter the H3C user role for the custom role')
            return custom_role
        return self.ROLE[role]

    def create_user(self, username, password, role, custom_role=''):
        self.configure(['local-user %s class manage' % username, 'password simple %s' % password,
                        'service-type ssh terminal',
                        'authorization-attribute user-role %s' % self.h3c_role(role, custom_role), 'quit'], password)

    def set_password(self, username, password, old_password=''):
        self.configure(['local-user %s class manage' % username, 'password simple %s' % password, 'quit'], password)

    def update_user(self, username, password, role, custom_role, existing):
        wanted = self.h3c_role(role, custom_role)
        keep = {wanted, 'network-operator'} if wanted != 'network-operator' else {wanted}
        old = [r.strip() for r in existing.get('raw_role', '').split(',') if r.strip() and r.strip() not in keep]
        self.configure(['local-user %s class manage' % username, 'password simple %s' % password,
                        'authorization-attribute user-role %s' % wanted]
                       + ['undo authorization-attribute user-role %s' % r for r in old] + ['quit'], password)

    def delete_user(self, username):
        self.configure(['undo local-user %s class manage' % username])

    def save(self):
        out = self.send('save force', read_timeout=120)
        self.check_errors(out)


DRIVERS = {d.vendor: d for d in (FortiGate, PaloAlto, CiscoIOS, CiscoASA, CiscoNXOS, Juniper, Huawei, H3C)}
NETMIKO_TO_VENDOR = {d.netmiko_type: d.vendor for d in DRIVERS.values()}
VENDOR_CHOICES = [('auto', 'Recognise automatically')] + [(d.vendor, d.label) for d in DRIVERS.values()]


def vendor_from_name(name):
    """Vendor from a platform or asset name ('' when unknown)."""
    n = (name or '').lower()
    for words, vendor in ((('forti',), 'fortinet'), (('palo', 'pan-os', 'panos'), 'paloalto'),
                          (('asa',), 'cisco_asa'), (('nx-os', 'nxos', 'nexus'), 'cisco_nxos'),
                          (('cisco', 'ios'), 'cisco_ios'), (('juniper', 'junos', 'srx'), 'juniper'),
                          (('huawei', 'vrp'), 'huawei'), (('h3c', 'comware'), 'h3c')):
        if any(w in n for w in words):
            return vendor
    return ''


DETECT = (  # (command, [(pattern, vendor)])
    ('get system status', [(r'FortiOS|FortiGate', 'fortinet')]),
    ('show system info', [(r'model:\s+PA', 'paloalto')]),
    ('show version', [(r'Adaptive Security Appliance|Cisco ASA', 'cisco_asa'), (r'NX-OS|Nexus Operating', 'cisco_nxos'),
                      (r'JUNOS', 'juniper'), (r'Cisco IOS|IOS-XE|Internetwork Operating System', 'cisco_ios')]),
    ('display version', [(r'H3C|Comware', 'h3c'), (r'Huawei|VRP', 'huawei')]),
)


def detect_vendor(params):
    """Recognises the vendor from the prompt and the version command (also H3C, which netmiko misses)."""
    from netmiko import ConnectHandler
    conn = ConnectHandler(device_type='terminal_server', **params)
    try:
        conn.write_channel('\n')
        prompt = conn.read_until_pattern(pattern=r'[>#$\]]\s*$', read_timeout=20).strip().splitlines()[-1]
        if prompt.startswith('<') or prompt.endswith(']'):
            order = [DETECT[3], DETECT[2], DETECT[0], DETECT[1]]
        elif re.search(r'FGT|Forti', prompt) or prompt.endswith(' #'):
            order = list(DETECT)
        elif '@' in prompt and prompt.endswith('>'):
            order = [DETECT[1], DETECT[2], DETECT[0], DETECT[3]]
        else:
            order = [DETECT[2], DETECT[0], DETECT[1], DETECT[3]]
        for command, patterns in order:
            out = conn.send_command_timing(command, read_timeout=20, last_read=1.5)
            for pattern, vendor in patterns:
                if re.search(pattern, out):
                    return vendor
        return ''
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


@contextlib.contextmanager
def tunnel(gateway, host, port, timeout=30):
    """(host, port) to connect to, through an SSH gateway when one is given."""
    if not gateway:
        yield host, port
        return
    from libs.ansible.modules_utils.remote_client import TimeoutSSHTunnelForwarder
    server = TimeoutSSHTunnelForwarder(
        (gateway['address'], int(gateway.get('port') or 22)), ssh_username=gateway['username'],
        ssh_password=gateway.get('password') or None, ssh_pkey=gateway.get('key_path') or None,
        connect_timeout=timeout, remote_bind_address=(host, int(port)), local_bind_address=('127.0.0.1', 0))
    server.start()
    try:
        yield '127.0.0.1', server.local_bind_port
    finally:
        server.stop(force=True)


def gateway_from_args(gateway_args):
    """Gateway settings from the Ansible ProxyCommand arguments XPAM builds for gateways."""
    if not gateway_args:
        return None
    from libs.ansible.modules_utils.remote_client import _parse_gateway_args
    g = _parse_gateway_args(gateway_args)
    if not g:
        return None
    return {'address': g['remote_addr'], 'port': g['port'], 'username': g['username'],
            'password': g['password'], 'key_path': g['key_path']}


@contextlib.contextmanager
def session(vendor, host, port, username, password='', key_file=None, enable_password='', gateway=None,
            timeout=30, options=None):
    """A connected Driver for the device; 'auto' recognises the vendor."""
    try:
        from netmiko import ConnectHandler
    except ImportError:
        raise DeviceError('The network device library (netmiko) is not installed')
    options = dict(options or {}, login_user=username)
    with tunnel(gateway, host, port, timeout) as (h, p):
        params = dict(host=h, port=int(p), username=username, password=password or '', secret=enable_password or '',
                      key_file=key_file or None, use_keys=bool(key_file), allow_agent=False, ssh_strict=False,
                      system_host_keys=False, conn_timeout=timeout, auth_timeout=timeout, banner_timeout=timeout,
                      timeout=max(timeout, 60), fast_cli=False)
        if not vendor or vendor == 'auto':
            try:
                vendor = detect_vendor(params)
            except Exception as e:
                raise DeviceError('Cannot reach the device: %s' % redact(e, password, enable_password)[:300])
            if not vendor:
                raise DeviceError('XPAM could not recognise the device; choose the vendor in the platform settings')
        cls = DRIVERS.get(vendor)
        if not cls:
            raise DeviceError('Unsupported vendor: %s' % vendor)
        try:
            conn = ConnectHandler(device_type=cls.netmiko_type, **params)
        except Exception as e:
            raise DeviceError('Cannot sign in to the device: %s' % redact(e, password, enable_password)[:300])
        try:
            driver = cls(conn, options)
            driver.elevate(enable_password)
            yield driver
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass
