"""
XPAM Automation: one result per server and run ("worked or not"), kept up to date while the job runs, so the
console shows the progress live; secret parameter values are masked in everything that is stored.
"""
import re
from datetime import timedelta

from django.utils import timezone

from .ansible.callback import TaskLogCallback
from .const import HostResult, HOST_OUTPUT_LIMIT

__all__ = ['HostResultCallback', 'mask', 'prepare_hosts', 'finish_hosts']

SHADOW = '********'
FINAL = {HostResult.worked, HostResult.failed, HostResult.unreachable, HostResult.timeout,
         HostResult.skipped, HostResult.stopped}


def mask(text, secrets):
    text = '' if text is None else str(text)
    for value in secrets or ():
        if value and len(str(value)) >= 3:
            text = text.replace(str(value), SHADOW)
    return text


# what SSH itself prints on a script's terminal (the script module runs with one): not the script's output
SSH_NOISE = re.compile(r'^(Warning: Permanently added .* to the list of known hosts\.|Connection to \S+ closed\.)\s*$')


def _quiet(text):
    return '\n'.join(line for line in text.replace('\r\n', '\n').split('\n') if not SSH_NOISE.match(line.strip())).strip()


def _clip(text):
    if len(text) > HOST_OUTPUT_LIMIT:
        return text[:HOST_OUTPUT_LIMIT] + '\n[... output cut at 1 MB]'
    return text


def prepare_hosts(execution, inventory):
    """A row per server of the run before it starts: waiting, or skipped with the reason (no account allowed...)."""
    from .models import JobExecutionHost
    excludes = dict(inventory.exclude_hosts or {})
    rows = []
    for asset in inventory.assets:
        reason = excludes.pop(asset.name, '')
        rows.append(JobExecutionHost(
            execution=execution, asset=asset, name=asset.name, org_id=execution.org_id,
            status=HostResult.skipped if reason else HostResult.waiting, reason=str(reason)[:1024],
        ))
    for name, reason in excludes.items():
        rows.append(JobExecutionHost(execution=execution, name=str(name)[:256], org_id=execution.org_id,
                                     status=HostResult.skipped, reason=str(reason)[:1024]))
    JobExecutionHost.objects.filter(execution=execution).delete()
    JobExecutionHost.objects.bulk_create(rows, ignore_conflicts=True)


def finish_hosts(execution, final_status, success_text='', reason=''):
    """At the end of a run: the servers still running worked (or timed out, were stopped...); never reached:
    skipped. `success_text`: a script's rule -- worked only when its output contains it."""
    from .models import JobExecutionHost
    now = timezone.now()
    rows = JobExecutionHost.objects.filter(execution=execution)
    for row in rows:
        if row.status in FINAL:
            continue
        if row.status == HostResult.running:
            row.status = final_status
            if final_status == HostResult.worked and success_text and success_text not in row.stdout:
                row.status = HostResult.failed
                row.reason = 'The output does not contain: %s' % success_text
        else:
            row.status = HostResult.stopped if final_status == HostResult.stopped else HostResult.skipped
            row.reason = row.reason or reason or 'The job ended before it reached this server'
        row.date_finished = row.date_finished or now
        row.save(update_fields=['status', 'reason', 'date_finished'])


class HostResultCallback(TaskLogCallback):
    """The job's log (as before), and the server rows updated as the events come in."""

    def __init__(self, task_id=None, execution=None, secrets=()):
        super().__init__(task_id)
        self.execution = execution
        self.secrets = [s for s in secrets if s]

    def write_task_output(self, output):
        return super().write_task_output(mask(output, self.secrets) if output else output)

    def _row(self, host):
        from .models import JobExecutionHost
        if not self.execution or not host:
            return None
        return JobExecutionHost.objects.filter(execution=self.execution, name=host).first()

    def _update(self, host, status=None, res=None, rc=None, reason=None, duration=None):
        try:
            row = self._row(host)
            if not row or row.status in FINAL:
                return
            now = timezone.now()
            row.date_start = row.date_start or now
            if duration:
                # (Ansible's own timing of the task on that server)
                row.date_start = min(row.date_start, now - timedelta(seconds=float(duration)))
            if res:
                out = _quiet(mask(res.get('stdout') or '', self.secrets))
                err = _quiet(mask(res.get('stderr') or '', self.secrets))
                if out:
                    row.stdout = _clip((row.stdout + '\n' if row.stdout else '') + out)
                if err:
                    row.stderr = _clip((row.stderr + '\n' if row.stderr else '') + err)
                if res.get('rc') is not None:
                    row.rc = res.get('rc')
            if rc is not None:
                row.rc = rc
            if reason:
                row.reason = mask(reason, self.secrets)[:1024]
            if status:
                row.status = status
                if status in FINAL:
                    row.date_finished = now
            row.save()
        except Exception:
            # (a result row must never stop the job)
            pass

    def runner_on_start(self, event_data, host=None, task=None, **kwargs):
        super().runner_on_start(event_data, host=host, task=task, **kwargs)
        self._update(host, status=HostResult.running)

    def runner_on_ok(self, event_data, host=None, task=None, res=None):
        super().runner_on_ok(event_data, host=host, task=task, res=res)
        self._update(host, status=HostResult.running, res=res or {}, duration=event_data.get('duration'))

    def runner_on_failed(self, event_data, host=None, task=None, res=None, **kwargs):
        super().runner_on_failed(event_data, host=host, task=task, res=res, **kwargs)
        if event_data.get('ignore_errors'):
            return self._update(host, status=HostResult.running, res=res or {})
        res = res or {}
        self._update(host, status=HostResult.failed, res=res, reason=res.get('msg') or '',
                     duration=event_data.get('duration'))

    def runner_on_unreachable(self, event_data, host=None, task=None, res=None, **kwargs):
        super().runner_on_unreachable(event_data, host=host, task=task, res=res, **kwargs)
        res = res or {}
        self._update(host, status=HostResult.unreachable, reason=res.get('msg') or '')
