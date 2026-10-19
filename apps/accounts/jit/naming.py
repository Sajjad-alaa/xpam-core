"""Names and passwords for just-in-time accounts."""
import hashlib
import hmac
import re
import secrets
import string

from django.conf import settings
from django.utils.translation import gettext as _

# Names that must never be created or removed by just-in-time access
RESERVED_USERNAMES = {
    'root', 'admin', 'administrator', 'guest', 'defaultaccount', 'wdagutilityaccount',
    'daemon', 'bin', 'sys', 'sync', 'nobody', 'system', 'sa', 'postgres', 'mysql', 'oracle',
    'sshd', 'www-data', 'ubuntu', 'ec2-user', 'centos', 'rocky', 'debian', 'krbtgt',
}
LINUX_MAX = 32
WINDOWS_MAX = 20
PASSWORD_SPECIALS = '-_.!@#%^+='
# Network device CLIs give meaning to "!", "?", "#" and similar characters
DEVICE_PASSWORD_SPECIALS = '-_.'


class JITNameError(ValueError):
    pass


def _short_hash(value, length):
    key = (settings.SECRET_KEY or 'xpam').encode()
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:length]


def clean_username(raw, max_length=WINDOWS_MAX):
    """
    A name that is valid both for Linux (useradd) and Windows local accounts:
    lower case letters, digits, '-' and '_', starting with a letter, at most `max_length`
    characters (20 by default, the Windows limit). A shortened name keeps a short hash of the
    full name, so two long names do not end up identical.
    """
    full = (raw or '').strip().lower()
    name = re.sub(r'[^a-z0-9_-]+', '-', full)
    name = re.sub(r'-{2,}', '-', name).strip('-_')
    if not name:
        raise JITNameError(_('The account name is empty after removing characters that are not allowed'))
    if not re.match(r'[a-z_]', name[0]):
        name = 'u' + name
    if len(name) > max_length:
        name = name[:max_length - 5].rstrip('-_') + '-' + _short_hash(full, 4)
    return name


def validate_username(name):
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', name or ''):
        raise JITNameError(_('Account names may only contain lower-case letters, digits, "-" and "_", '
                             'and must start with a letter'))
    if len(name) > WINDOWS_MAX:
        raise JITNameError(_('Account names may have at most 20 characters (Windows limit)'))
    if name in RESERVED_USERNAMES:
        raise JITNameError(_('"%s" is a reserved system account name') % name)
    return name


def build_username(policy, user, new_session=False):
    """The account name a policy gives to `user` (a new one for every call with random per session)."""
    from accounts.models import JITPolicy
    mode = policy.username_mode
    prefix = policy.username_prefix or ''
    if mode == JITPolicy.UsernameMode.specific:
        name = policy.specific_username
    elif mode == JITPolicy.UsernameMode.random_fixed:
        name = prefix + 'u' + _short_hash(f'jit-user:{user.id}', 9)
    elif mode == JITPolicy.UsernameMode.random_session:
        name = prefix + 's' + secrets.token_hex(5)
    else:
        name = prefix + user.username
    return validate_username(clean_username(name))


def generate_password(length=24, specials=PASSWORD_SPECIALS):
    """Meets the Windows complexity rules and is safe to pass through Ansible."""
    alphabet = string.ascii_letters + string.digits + specials
    while True:
        value = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in value) and any(c.isupper() for c in value)
                and any(c.isdigit() for c in value) and any(c in specials for c in value)
                and value[0].isalnum()):
            return value
