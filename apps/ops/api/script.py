"""
XPAM Automation: scripts (write, submit for approval, approve, run) and the result of every server of a run (list,
CSV export, run again on the servers where it did not work).
"""
import csv
import json
import math
import uuid

from django.conf import settings
from django.db import transaction
from django.db.models import Q, F
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response

from common.utils import get_request_ip_or_data
from orgs.mixins.api import OrgBulkModelViewSet
from ..const import (
    ScriptState, ScriptSharing, Types, HostResult, COMMAND_EXECUTION_DISABLED, AUTOMATION_NOT_LICENSED,
    automation_licensed,
)
from ..models import Script, Job, JobExecution, JobExecutionHost
from ..serializers.script import (
    ScriptSerializer, ScriptRunSerializer, ScriptReviewSerializer, JobExecutionHostSerializer,
    RetryFailedSerializer, check_values,
)
from ..utils import merge_nodes_and_assets

__all__ = ['ScriptViewSet', 'start_execution', 'host_results_response', 'retry_failed']

FORKS = 20


def check_automation(request):
    if not settings.SECURITY_COMMAND_EXECUTION:
        raise PermissionDenied(_('Command execution disabled'))
    if not automation_licensed():
        raise PermissionDenied(AUTOMATION_NOT_LICENSED)


def start_execution(execution, server_count, timeout):
    """Starts a run in the worker once the transaction is saved. Its time limit follows the job: the time per
    server for every round of FORKS servers, plus a margin (the upstream default stopped every job after 60 s)."""
    from ..tasks import run_ops_job_execution
    rounds = max(1, math.ceil(max(1, server_count) / FORKS))
    soft = max(60, int(timeout or 0)) * rounds + 180
    transaction.on_commit(lambda: run_ops_job_execution.apply_async(
        (str(execution.id),), task_id=str(execution.id), soft_time_limit=soft, time_limit=soft + 60))


def create_script_run(request, script, assets, runas, runas_policy, plain, secret, nodes=()):
    from .job import LoginAssetACLCheckMixin
    refusal = script.run_refusal(request.user, assets)
    if refusal:
        raise PermissionDenied(refusal)
    LoginAssetACLCheckMixin().check_login_asset_acls(request.user, assets, runas, get_request_ip_or_data(request))
    info = {
        'script_id': str(script.id), 'name': script.name, 'version': script.version, 'content': script.content,
        'interpreter': script.interpreter, 'extension': script.extension, 'executable': script.executable,
        'timeout': script.timeout, 'success_text': script.success_text, 'values': plain,
        'secret_names': sorted(secret),
    }
    job = Job.objects.create(
        name='script-%s' % uuid.uuid4().hex[:12], instant=True, type=Types.script, script=script,
        module=script.job_module, args=json.dumps(info), runas=runas, runas_policy=runas_policy,
        timeout=script.timeout, creator=request.user, org_id=script.org_id,
    )
    job.assets.set(assets)
    execution = job.create_execution()
    execution.creator = request.user
    execution.parameters = {'values': plain}
    execution.secret_parameters = json.dumps(secret) if secret else ''
    execution.save()
    start_execution(execution, len(assets), script.timeout)
    return execution


class ScriptViewSet(OrgBulkModelViewSet):
    model = Script
    serializer_class = ScriptSerializer
    search_fields = ('name', 'comment')
    filterset_fields = ('state', 'interpreter', 'sharing')
    ordering_fields = ('name', 'state', 'date_updated', 'date_created')
    rbac_perms = {
        'submit': 'ops.change_script',
        'approve': 'ops.approve_script',
        'reject': 'ops.approve_script',
        'run': 'ops.add_job',
        'history': 'ops.view_script',
    }

    def check_permissions(self, request):
        if not automation_licensed():
            return self.permission_denied(request, AUTOMATION_NOT_LICENSED)
        return super().check_permissions(request)

    def can_review(self):
        return self.request.user.has_perm('ops.approve_script')

    def get_queryset(self):
        queryset = super().get_queryset()
        user = self.request.user
        visible = Q(creator=user) | Q(sharing=ScriptSharing.org, state=ScriptState.approved,
                                      approved_version=F('version'))
        if self.can_review():
            visible |= Q(state=ScriptState.pending)
        return queryset.filter(visible)

    def get_serializer_class(self):
        return {
            'run': ScriptRunSerializer, 'approve': ScriptReviewSerializer, 'reject': ScriptReviewSerializer,
        }.get(self.action, ScriptSerializer)

    def check_author(self, script):
        if script.creator_id != self.request.user.id:
            raise PermissionDenied(_('Only the author can change this script'))

    def perform_update(self, serializer):
        self.check_author(serializer.instance)
        serializer.save()

    def perform_destroy(self, instance):
        if instance.creator_id != self.request.user.id and not self.can_review():
            raise PermissionDenied(_('Only the author or an approver can delete this script'))
        Job.objects.filter(script=instance).update(script=None)
        instance.delete()

    def allow_bulk_destroy(self, qs, filtered):
        return False

    @action(methods=['post'], detail=True)
    def submit(self, request, *args, **kwargs):
        script = self.get_object()
        self.check_author(script)
        if script.state not in (ScriptState.draft, ScriptState.rejected):
            raise ValidationError(_('Only a draft can be submitted'))
        script.state = ScriptState.pending
        script.save(update_fields=['state', 'date_updated'])
        return Response(ScriptSerializer(script, context={'request': request}).data)

    def review(self, request, approve):
        script = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if script.state != ScriptState.pending:
            raise ValidationError(_('The script is not waiting for approval'))
        # four eyes: another person than the author approves (a system administrator may approve their own)
        if script.creator_id == request.user.id and not request.user.is_superuser:
            raise PermissionDenied(_('The author cannot approve their own script'))
        comment = serializer.validated_data.get('comment', '')
        if approve:
            script.approve(request.user, comment)
        else:
            script.state = ScriptState.rejected
            script.review_comment = comment
            script.approved_by = request.user
            script.date_approved = timezone.now()
        script.save()
        return Response(ScriptSerializer(script, context={'request': request}).data)

    @action(methods=['post'], detail=True)
    def approve(self, request, *args, **kwargs):
        return self.review(request, True)

    @action(methods=['post'], detail=True)
    def reject(self, request, *args, **kwargs):
        return self.review(request, False)

    @action(methods=['post'], detail=True)
    def run(self, request, *args, **kwargs):
        check_automation(request)
        script = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        assets = merge_nodes_and_assets(data.get('nodes', []), data.get('assets', []), request.user)
        if not assets:
            raise ValidationError(_('None of the chosen servers is available to you'))
        plain, secret = check_values(script, data.get('parameters'))
        execution = create_script_run(request, script, list(assets), data['runas'], data['runas_policy'],
                                      plain, secret)
        return Response({'execution': str(execution.id), 'task_id': str(execution.id)}, status=status.HTTP_201_CREATED)


# ---------------------------------------------------------------- results of a run (any job type)
CSV_FIELDS = ['name', 'status', 'rc', 'duration', 'reason', 'date_start', 'date_finished', 'stdout', 'stderr']


def host_results_response(request, execution):
    rows = JobExecutionHost.objects.filter(execution=execution)
    wanted = request.query_params.get('status')
    if wanted:
        rows = rows.filter(status__in=wanted.split(','))
    if request.query_params.get('format') == 'csv':
        response = HttpResponse(content_type='text/csv; charset=utf-8')
        response['Content-Disposition'] = 'attachment; filename="run-%s.csv"' % str(execution.id)[:8]
        writer = csv.writer(response)
        writer.writerow(CSV_FIELDS)
        for row in rows:
            values = [row.name, row.get_status_display(), row.rc, row.duration, row.reason, row.date_start,
                      row.date_finished, row.stdout, row.stderr]
            # (a cell starting with = + - @ would be a formula in a spreadsheet)
            writer.writerow(["'" + v if isinstance(v, str) and v[:1] in '=+-@\t\r' else v for v in values])
        return response
    counts = {}
    for value in JobExecutionHost.objects.filter(execution=execution).values_list('status', flat=True):
        counts[value] = counts.get(value, 0) + 1
    return Response({
        'execution': str(execution.id), 'status': execution.status, 'is_finished': execution.is_finished,
        'totals': counts, 'results': JobExecutionHostSerializer(rows, many=True).data,
    })


RETRY_STATUSES = (HostResult.failed, HostResult.unreachable, HostResult.timeout, HostResult.stopped)


def retry_failed(request, execution):
    """The same job once more, on the servers where it did not work (failed, unreachable, timed out, stopped)."""
    check_automation(request) if execution.job_type != Types.upload_file else None
    job = execution.job
    if not job or not execution.is_finished:
        raise ValidationError(_('The run has not ended yet'))
    if job.type == Types.upload_file:
        raise ValidationError(_('Upload the files again'))
    serializer = RetryFailedSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    asset_ids = JobExecutionHost.objects.filter(execution=execution, status__in=RETRY_STATUSES,
                                                asset__isnull=False).values_list('asset_id', flat=True)
    from assets.models import Asset
    assets = list(Asset.objects.filter(id__in=list(asset_ids)))
    if not assets:
        raise ValidationError(_('There is no server to run it on again'))
    if job.type == Types.script:
        script = get_object_or_404(Script, id=job.script_id) if job.script_id else None
        if not script:
            raise ValidationError(_('The script no longer exists'))
        info = json.loads(job.args or '{}')
        if script.version != info.get('version'):
            raise ValidationError(_('The script changed since this run; start it again'))
        values = dict(info.get('values') or {})
        values.update(serializer.validated_data.get('parameters') or {})
        plain, secret = check_values(script, values)
        new = create_script_run(request, script, assets, job.runas, job.runas_policy, plain, secret)
    else:
        if job.creator_id != request.user.id:
            raise PermissionDenied(_('You do not have permission for the current job.'))
        new_job = Job.objects.create(
            name='%s-retry-%s' % (job.name[:100], uuid.uuid4().hex[:6]), instant=True, type=job.type,
            module=job.module, args=job.args, playbook=job.playbook, runas=job.runas,
            runas_policy=job.runas_policy, timeout=job.timeout, chdir=job.chdir, creator=request.user,
            org_id=job.org_id,
        )
        new_job.assets.set(assets)
        new = new_job.create_execution()
        new.creator = request.user
        new.parameters = execution.parameters
        new.save()
        start_execution(new, len(assets), job.timeout)
    return Response({'execution': str(new.id), 'task_id': str(new.id), 'servers': len(assets)},
                    status=status.HTTP_201_CREATED)
