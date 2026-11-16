"""XPAM Automation: scripts, their runs and the result of every server."""
import json

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from assets.models import Asset, Node
from common.serializers.fields import LabeledChoiceField, ObjectRelatedField, ReadableHiddenField
from orgs.mixins.serializers import BulkOrgResourceModelSerializer
from ..const import ScriptInterpreter, ScriptParamType, ScriptSharing, ScriptState, HostResult, RunasPolicies
from ..models import Script, JobExecutionHost
from ..models.script import PARAM_NAME, RESERVED_PARAM

__all__ = [
    'ScriptSerializer', 'ScriptRunSerializer', 'ScriptReviewSerializer', 'JobExecutionHostSerializer',
    'RetryFailedSerializer', 'check_values',
]

# what changes the script that runs: a change needs a new approval
CONTENT_FIELDS = ('content', 'interpreter', 'parameters', 'timeout', 'success_text')


class ScriptSerializer(BulkOrgResourceModelSerializer):
    creator = ReadableHiddenField(default=serializers.CurrentUserDefault())
    interpreter = LabeledChoiceField(choices=ScriptInterpreter.choices, label=_('Interpreter'))
    sharing = LabeledChoiceField(choices=ScriptSharing.choices, label=_('Shared with'), required=False)
    state = LabeledChoiceField(choices=ScriptState.choices, label=_('State'), read_only=True)
    approved_by = ObjectRelatedField(read_only=True, label=_('Approved by'))
    creator_display = serializers.CharField(source='creator.name', read_only=True, default='', label=_('Creator'))
    is_approved = serializers.BooleanField(read_only=True, label=_('Approved'))
    is_mine = serializers.SerializerMethodField(label=_('Mine'))

    class Meta:
        model = Script
        read_only_fields = [
            'id', 'state', 'version', 'approved_version', 'approved_by', 'date_approved', 'review_comment',
            'creator_display', 'is_approved', 'is_mine', 'date_created', 'date_updated',
        ]
        fields = read_only_fields + [
            'name', 'interpreter', 'content', 'parameters', 'timeout', 'success_text', 'changes_server', 'sharing',
            'comment', 'creator',
        ]

    def get_is_mine(self, obj):
        request = self.context.get('request')
        return bool(request and obj.creator_id == request.user.id)

    @staticmethod
    def validate_content(value):
        if not value or not value.strip():
            raise serializers.ValidationError(_('The script is empty'))
        if '\x00' in value:
            raise serializers.ValidationError(_('The script contains a NUL character'))
        return value.replace('\r\n', '\n')

    @staticmethod
    def validate_timeout(value):
        if not 10 <= value <= 86400:
            raise serializers.ValidationError(_('Between 10 seconds and 24 hours'))
        return value

    @staticmethod
    def validate_parameters(value):
        if isinstance(value, str):
            # (a form may send the list as JSON text)
            try:
                value = json.loads(value or '[]')
            except ValueError:
                raise serializers.ValidationError(_('A list of at most 50 parameters'))
        if not isinstance(value, list) or len(value) > 50:
            raise serializers.ValidationError(_('A list of at most 50 parameters'))
        names, cleaned = set(), []
        for p in value:
            if not isinstance(p, dict):
                raise serializers.ValidationError(_('Each parameter is an object'))
            name = str(p.get('name', ''))
            if not PARAM_NAME.match(name):
                raise serializers.ValidationError(
                    _('Parameter name "%s": letters, digits and _, not starting with a digit') % name)
            if RESERVED_PARAM.match(name):
                raise serializers.ValidationError(_('Parameter name "%s" is reserved') % name)
            if name.upper() in names:
                raise serializers.ValidationError(_('Parameter "%s" is defined twice') % name)
            names.add(name.upper())
            ptype = p.get('type', ScriptParamType.text)
            if ptype not in ScriptParamType.values:
                raise serializers.ValidationError(_('Parameter "%s": unknown type') % name)
            choices = [str(c) for c in p.get('choices') or []]
            if ptype == ScriptParamType.choice and not choices:
                raise serializers.ValidationError(_('Parameter "%s": a choice needs its options') % name)
            item = {
                'name': name, 'type': ptype, 'label': str(p.get('label') or name)[:128],
                'required': bool(p.get('required', False)), 'help': str(p.get('help') or '')[:512],
            }
            if choices:
                item['choices'] = choices[:100]
            if ptype != ScriptParamType.secret and p.get('default') not in (None, ''):
                item['default'] = str(p.get('default'))[:4096]
            cleaned.append(item)
        return cleaned

    def create(self, validated_data):
        validated_data['state'] = ScriptState.draft
        return super().create(validated_data)

    def update(self, instance, validated_data):
        if any(k in validated_data and validated_data[k] != getattr(instance, k) for k in CONTENT_FIELDS):
            instance.changed()
        elif 'sharing' in validated_data and validated_data['sharing'] != instance.sharing \
                and validated_data['sharing'] == ScriptSharing.org:
            # (sharing it needs an approval too)
            instance.changed()
        validated_data.pop('creator', None)
        return super().update(instance, validated_data)


def check_values(script, values, require_secrets=True):
    """The values of a run, checked against the script's parameters: (plain values, secret values)."""
    values = values or {}
    if not isinstance(values, dict):
        raise serializers.ValidationError({'parameters': _('An object of parameter values')})
    plain, secret, errors = {}, {}, {}
    known = {p['name'] for p in script.parameters or []}
    for extra in set(values) - known:
        errors[extra] = _('This script has no such parameter')
    for p in script.parameters or []:
        name, ptype = p['name'], p.get('type', 'text')
        value = values.get(name, p.get('default'))
        if value is None or value == '':
            if p.get('required') and (ptype != ScriptParamType.secret or require_secrets):
                errors[name] = _('Required')
            continue
        value = str(value)
        if len(value) > 4096:
            errors[name] = _('At most 4096 characters')
        elif '\x00' in value:
            errors[name] = _('Invalid value')
        elif ptype == ScriptParamType.number:
            try:
                float(value)
            except ValueError:
                errors[name] = _('A number')
        elif ptype == ScriptParamType.choice and value not in p.get('choices', []):
            errors[name] = _('One of: %s') % ', '.join(p.get('choices', []))
        elif ptype == ScriptParamType.boolean:
            if value.lower() not in ('true', 'false', '1', '0', 'yes', 'no'):
                errors[name] = _('Yes or no')
            value = 'true' if value.lower() in ('true', '1', 'yes') else 'false'
        (secret if ptype == ScriptParamType.secret else plain)[name] = value
    if errors:
        raise serializers.ValidationError({'parameters': errors})
    return plain, secret


class ScriptRunSerializer(serializers.Serializer):
    assets = serializers.PrimaryKeyRelatedField(queryset=Asset.objects, many=True, required=False, label=_('Assets'))
    nodes = serializers.PrimaryKeyRelatedField(queryset=Node.objects, many=True, required=False, label=_('Nodes'))
    runas = serializers.CharField(max_length=128, default='root', label=_('Run as'))
    runas_policy = serializers.ChoiceField(choices=RunasPolicies.choices, default=RunasPolicies.privileged_first)
    parameters = serializers.JSONField(required=False, default=dict, label=_('Parameters'))

    def validate(self, attrs):
        if not attrs.get('assets') and not attrs.get('nodes'):
            raise serializers.ValidationError(_('Choose the servers'))
        return attrs


class ScriptReviewSerializer(serializers.Serializer):
    comment = serializers.CharField(max_length=1024, required=False, allow_blank=True, default='')


class RetryFailedSerializer(serializers.Serializer):
    parameters = serializers.JSONField(required=False, default=dict, label=_('Secret parameters'))


class JobExecutionHostSerializer(serializers.ModelSerializer):
    status = LabeledChoiceField(choices=HostResult.choices, read_only=True, label=_('Result'))
    duration = serializers.FloatField(read_only=True, label=_('Duration'))

    class Meta:
        model = JobExecutionHost
        fields = ['id', 'name', 'asset', 'status', 'rc', 'stdout', 'stderr', 'reason', 'date_start',
                  'date_finished', 'duration']
        read_only_fields = fields
