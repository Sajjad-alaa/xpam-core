from django.db import models
from django.utils.translation import gettext_lazy as _, pgettext_lazy

from common.utils import string_punctuation


class SSHKeyStrategy(models.TextChoices):
    add = 'add', _('Append SSH KEY')
    set = 'set', _('Empty and append SSH KEY')
    set_jms = 'set_jms', _('Replace (Replace only keys pushed by system) ')


class PasswordStrategy(models.TextChoices):
    custom = 'custom', _('Custom password')
    random_one = 'random_one', _('All assets use the same random password')
    random_all = 'random_all', _('All assets use different random password')


DEFAULT_PASSWORD_LENGTH = 30
DEFAULT_PASSWORD_RULES = {
    'length': DEFAULT_PASSWORD_LENGTH,
    'symbol_set': string_punctuation
}


class CreateMethods(models.TextChoices):
    blank = 'blank', _('Blank')
    vcs = 'vcs', _('VCS')


class Types(models.TextChoices):
    adhoc = 'adhoc', _('Adhoc')
    playbook = 'playbook', _('Playbook')
    upload_file = 'upload_file', _('Upload File')
    script = 'script', _('Script')


# XPAM Automation: scripts
class ScriptInterpreter(models.TextChoices):
    bash = 'bash', 'Bash'
    sh = 'sh', 'sh'
    python3 = 'python3', 'Python 3'
    powershell = 'powershell', 'PowerShell'


SCRIPT_INTERPRETERS = {
    # interpreter: (file extension, executable on the server, job module: which connection it needs)
    'bash': ('sh', '/bin/bash', 'shell'),
    'sh': ('sh', '/bin/sh', 'shell'),
    'python3': ('py', 'python3', 'shell'),
    'powershell': ('ps1', '', 'win_shell'),
}


class ScriptState(models.TextChoices):
    draft = 'draft', _('Draft')
    pending = 'pending', _('Waiting for approval')
    approved = 'approved', _('Approved')
    rejected = 'rejected', _('Rejected')


class ScriptSharing(models.TextChoices):
    private = 'private', _('Only me')
    org = 'org', _('Organization')


class ScriptParamType(models.TextChoices):
    text = 'text', _('Text')
    number = 'number', _('Number')
    choice = 'choice', _('Choice')
    boolean = 'boolean', _('Yes/No')
    secret = 'secret', _('Secret')


class HostResult(models.TextChoices):
    """What happened on one server in one run."""
    waiting = 'waiting', _('Waiting')
    running = 'running', _('Running')
    worked = 'worked', _('Worked')
    failed = 'failed', _('Failed')
    unreachable = 'unreachable', _('Unreachable')
    timeout = 'timeout', _('Timed out')
    skipped = 'skipped', _('Skipped')
    stopped = 'stopped', _('Stopped')


HOST_OUTPUT_LIMIT = 1024 * 1024


class RunasPolicies(models.TextChoices):
    privileged_only = 'privileged_only', _('Privileged only')
    privileged_first = 'privileged_first', _('Privileged first')
    skip = 'skip', _('Skip')


class JobModules(models.TextChoices):
    shell = 'shell', _('Shell')
    winshell = 'win_shell', _('Powershell')
    python = 'python', _('Python')
    mysql = 'mysql', _('MySQL')
    postgresql = 'postgresql', _('PostgreSQL')
    sqlserver = 'sqlserver', _('SQLServer')
    raw = 'raw', _('Raw')
    huawei = 'huawei', _('HUAWEI')


class AdHocModules(models.TextChoices):
    shell = 'shell', _('Shell')
    winshell = 'win_shell', _('Powershell')
    python = 'python', _('Python')
    mysql = 'mysql', _('MySQL')
    mariadb = 'mariadb', _('MariaDB')
    postgresql = 'postgresql', _('PostgreSQL')
    sqlserver = 'sqlserver', _('SQLServer')
    oracle = 'oracle', _('Oracle')
    raw = 'raw', _('Raw')


class JobStatus(models.TextChoices):
    running = 'running', _('Running')
    success = 'success', _('Success')
    timeout = 'timeout', _('Timeout')
    failed = 'failed', _('Failed')


# celery 日志完成之后，写入的魔法字符，作为结束标记
CELERY_LOG_MAGIC_MARK = b'\x00\x00\x00\x00\x00'

COMMAND_EXECUTION_DISABLED = _('Command execution disabled')
AUTOMATION_NOT_LICENSED = _('Automation is not part of this licence')


def automation_licensed():
    """XPAM: Automation (commands, scripts and playbooks run on servers) is a licensed feature; file transfer is not."""
    try:
        from xpack.utils import has_automation_license
        return bool(has_automation_license())
    except Exception:
        return False


class Scope(models.TextChoices):
    public = 'public', pgettext_lazy("scope", 'Public')
    private = 'private', _('Private')


class FieldType(models.TextChoices):
    text = 'text', _('Text')
    select = 'select', _('Select')
