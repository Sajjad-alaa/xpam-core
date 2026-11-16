"""
XPAM Automation: scripts sent to servers, and what happened on every server of a run.

A Script is a named, versioned file (Bash, sh, Python 3, PowerShell) with typed parameters. Its parameters reach the
script as environment variables, never pasted into its text. Owner rules (2026-11-16): a script that is not approved
runs only for its author and only on servers that are not production; sharing it with the organization or running
it on production needs an administrator's approval (another person than the author, unless a system
administrator); every change of the script needs a new approval.
"""
import re

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from orgs.mixins.models import JMSOrgBaseModel
from ..const import (
    ScriptInterpreter, ScriptState, ScriptSharing, ScriptParamType, HostResult, SCRIPT_INTERPRETERS,
)

__all__ = ['Script', 'JobExecutionHost', 'is_production', 'PARAM_NAME', 'RESERVED_PARAM']

PARAM_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')
# (names the script's environment needs for itself)
RESERVED_PARAM = re.compile(r'^(PATH|HOME|USER|SHELL|IFS|ENV|BASH_ENV|PS4|LD_\w*|PYTHON\w*|ANSIBLE_\w*|XPAM_\w*|JMS_\w*)$',
                            re.IGNORECASE)
PRODUCTION_TAGS = {('env', 'production'), ('env', 'prod'), ('environment', 'production'), ('environment', 'prod')}


def is_production(asset):
    """A server counts as production when it carries the tag env:production (or environment:production, :prod),
    or a tag named production."""
    for label in asset.labels.all():
        name = (label.label.name or '').strip().lower()
        value = (label.label.value or '').strip().lower()
        if name == 'production' or (name, value) in PRODUCTION_TAGS:
            return True
    return False


class Script(JMSOrgBaseModel):
    name = models.CharField(max_length=128, verbose_name=_('Name'))
    interpreter = models.CharField(max_length=16, choices=ScriptInterpreter.choices, default=ScriptInterpreter.bash,
                                   verbose_name=_('Interpreter'))
    content = models.TextField(max_length=262144, verbose_name=_('Script'))
    parameters = models.JSONField(default=list, verbose_name=_('Parameters'))
    timeout = models.IntegerField(default=600, verbose_name=_('Timeout (Seconds)'))
    success_text = models.CharField(max_length=256, default='', blank=True,
                                     verbose_name=_('Worked when the output contains'))
    changes_server = models.BooleanField(default=True, verbose_name=_('Changes the server'))
    sharing = models.CharField(max_length=16, choices=ScriptSharing.choices, default=ScriptSharing.private,
                               verbose_name=_('Shared with'))
    state = models.CharField(max_length=16, choices=ScriptState.choices, default=ScriptState.draft,
                             verbose_name=_('State'))
    version = models.IntegerField(default=1, verbose_name=_('Version'))
    approved_version = models.IntegerField(null=True, blank=True, verbose_name=_('Approved version'))
    approved_by = models.ForeignKey('users.User', null=True, blank=True, on_delete=models.SET_NULL,
                                    related_name='+', verbose_name=_('Approved by'))
    date_approved = models.DateTimeField(null=True, blank=True, verbose_name=_('Date approved'))
    review_comment = models.CharField(max_length=1024, default='', blank=True, verbose_name=_('Review comment'))
    creator = models.ForeignKey('users.User', null=True, on_delete=models.SET_NULL, related_name='+',
                                verbose_name=_('Creator'))

    class Meta:
        verbose_name = _('Script')
        unique_together = [('name', 'org_id')]
        ordering = ['name']
        permissions = [('approve_script', _('Can approve script'))]

    def __str__(self):
        return self.name

    @property
    def is_approved(self):
        return self.state == ScriptState.approved and self.approved_version == self.version

    @property
    def extension(self):
        return SCRIPT_INTERPRETERS[self.interpreter][0]

    @property
    def executable(self):
        return SCRIPT_INTERPRETERS[self.interpreter][1]

    @property
    def job_module(self):
        return SCRIPT_INTERPRETERS[self.interpreter][2]

    @property
    def secret_names(self):
        return [p['name'] for p in self.parameters or [] if p.get('type') == ScriptParamType.secret]

    def visible_to(self, user):
        return self.creator_id == user.id or (self.sharing == ScriptSharing.org and self.is_approved)

    def run_refusal(self, user, assets):
        """Why `user` may not run this script on `assets` now ('' when allowed)."""
        if not self.visible_to(user):
            return _('This script is not shared with you')
        if self.is_approved:
            return ''
        if self.creator_id != user.id:
            return _('Only the author can run a script that is not approved')
        production = [a.name for a in assets if is_production(a)]
        if production:
            return _('A script that is not approved cannot run on production servers: %s') % ', '.join(production[:5])
        return ''

    def changed(self):
        """A change of what runs: a new version, and the approval is gone."""
        self.version += 1
        self.state = ScriptState.draft
        self.date_approved = None

    def approve(self, user, comment=''):
        self.state = ScriptState.approved
        self.approved_version = self.version
        self.approved_by = user
        self.date_approved = timezone.now()
        self.review_comment = comment or ''


class JobExecutionHost(JMSOrgBaseModel):
    """What happened on one server in one run (commands, scripts, playbooks, file transfer)."""
    execution = models.ForeignKey('ops.JobExecution', on_delete=models.CASCADE, related_name='hosts',
                                  verbose_name=_('Execution'))
    asset = models.ForeignKey('assets.Asset', null=True, blank=True, on_delete=models.SET_NULL, related_name='+',
                              verbose_name=_('Asset'))
    name = models.CharField(max_length=256, verbose_name=_('Server'))
    status = models.CharField(max_length=16, choices=HostResult.choices, default=HostResult.waiting,
                              verbose_name=_('Result'))
    rc = models.IntegerField(null=True, blank=True, verbose_name=_('Exit code'))
    stdout = models.TextField(default='', blank=True, verbose_name=_('Output'))
    stderr = models.TextField(default='', blank=True, verbose_name=_('Errors'))
    reason = models.CharField(max_length=1024, default='', blank=True, verbose_name=_('Reason'))
    date_start = models.DateTimeField(null=True, blank=True, verbose_name=_('Date start'))
    date_finished = models.DateTimeField(null=True, blank=True, verbose_name=_('Date finished'))

    class Meta:
        verbose_name = _('Result per server')
        ordering = ['name']
        unique_together = [('execution', 'name')]

    @property
    def duration(self):
        if self.date_start and self.date_finished:
            return round((self.date_finished - self.date_start).total_seconds(), 1)
        return None
