from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from common.serializers.fields import LabeledChoiceField, JSONManyToManyField, ObjectRelatedField
from orgs.mixins.serializers import OrgResourceModelSerializerMixin
from orgs.models import Organization
from orgs.utils import get_current_org_id
from tickets.const import TicketLevel, TicketType
from tickets.models import TicketFlow, ApprovalRule
from users.models import User

__all__ = ['TicketFlowSerializer', 'TicketFlowOptionSerializer']


class TicketFlowApproveSerializer(serializers.ModelSerializer):
    users = JSONManyToManyField(label=_('User'))

    class Meta:
        model = ApprovalRule
        fields = ['level', 'users']
        read_only_fields = ['level']

    def validate_users(self, value):
        rule = ApprovalRule()
        rule.users.set(value)
        assignees = rule.get_assignees(org_id=get_current_org_id())
        if not assignees.exists():
            error = _('No approvers matched. Please update the approval rule')
            raise serializers.ValidationError(error)
        return value


class TicketFlowSerializer(OrgResourceModelSerializerMixin):
    name = serializers.CharField(
        required=True, allow_blank=False, max_length=128, label=_('Name')
    )
    type = LabeledChoiceField(
        choices=TicketType.choices, read_only=True, label=_('Type')
    )
    rules = TicketFlowApproveSerializer(many=True, required=True)
    cc_users = ObjectRelatedField(
        queryset=User.objects, many=True, required=False,
        attrs=('id', 'name', 'username'), label=_('CC users')
    )
    jit_policies = serializers.SerializerMethodField(label=_('JIT policies'))

    class Meta:
        model = TicketFlow
        fields_mini = ['id', 'name', 'type']
        fields_small = fields_mini + [
            'approval_level', 'jit_policies', 'created_by', 'date_created',
            'date_updated', 'org_id', 'org_name'
        ]
        fields = fields_small + ['rules', 'cc_users']
        read_only_fields = ['jit_policies', 'created_by', 'date_created', 'date_updated']

    @staticmethod
    def get_jit_policies(obj):
        if obj.type != TicketType.apply_asset:
            return []
        try:
            from accounts.models import JITPolicy
            from accounts.jit.selfservice import org_flows
            current_org_id = str(get_current_org_id())
            explicit = list(
                JITPolicy.objects.filter(
                    org_id=current_org_id,
                    approval_route=JITPolicy.ApprovalRoute.flow,
                    approval_flow_id=obj.id,
                ).values('id', 'name', 'auto_approve', 'auto_approve_max_hours')[:20]
            )
            result = [
                {
                    'id': str(p['id']),
                    'name': p['name'],
                    'auto_approve': p['auto_approve'],
                    'auto_approve_max_hours': p['auto_approve_max_hours'],
                    'via_default': False,
                }
                for p in explicit
            ]
            seen = {r['id'] for r in result}
            first_flow = org_flows(current_org_id).first()
            if first_flow and str(first_flow.id) == str(obj.id):
                defaults = list(
                    JITPolicy.objects.filter(
                        org_id=current_org_id,
                        approval_route=JITPolicy.ApprovalRoute.flow,
                        approval_flow__isnull=True,
                    ).values('id', 'name', 'auto_approve', 'auto_approve_max_hours')[:20]
                )
                for p in defaults:
                    pid = str(p['id'])
                    if pid not in seen:
                        result.append({
                            'id': pid,
                            'name': p['name'],
                            'auto_approve': p['auto_approve'],
                            'auto_approve_max_hours': p['auto_approve_max_hours'],
                            'via_default': True,
                        })
            return result
        except Exception:
            return []

    def validate(self, attrs):
        attrs = super().validate(attrs)
        name = attrs.get('name', getattr(self.instance, 'name', ''))
        ticket_type = attrs.get(
            'type', getattr(self.instance, 'type', TicketType.apply_asset)
        )
        current_org_id = str(get_current_org_id())
        flows = TicketFlow.objects.filter(
            org_id=current_org_id, name__iexact=name, type=ticket_type
        )
        if self.instance and self.instance.org_id == current_org_id:
            flows = flows.exclude(id=self.instance.id)
        if flows.exists():
            error = _('A ticket flow with the same name and type already exists')
            raise serializers.ValidationError({'name': error})

        approval_level = attrs.get(
            'approval_level', getattr(self.instance, 'approval_level', TicketLevel.one)
        )
        rules = attrs.get('rules')
        if rules is not None and len(rules) != approval_level:
            error = _('The number of approval rules must match the approval level')
            raise serializers.ValidationError({'rules': error})
        return attrs

    def create_or_update(self, action, validated_data, instance=None):
        children = validated_data.pop('rules', [])
        if instance is None:
            instance = getattr(super(), action)(validated_data)
        else:
            instance = getattr(super(), action)(instance, validated_data)
            instance.rules.all().delete()

        child_instances = [
            instance.rules.model.objects.create(**data, level=level)
            for level, data in enumerate(children, 1)
        ]
        instance.rules.set(child_instances)
        return instance

    def create(self, validated_data):
        validated_data['type'] = TicketType.apply_asset
        return self.create_or_update('create', validated_data)

    def update(self, instance, validated_data):
        current_org_id = str(get_current_org_id())
        root_org_id = Organization.ROOT_ID
        if instance.org_id == root_org_id and current_org_id != root_org_id:
            instance = self.create(validated_data)
        else:
            instance = self.create_or_update('update', validated_data, instance)
        return instance


class TicketFlowOptionSerializer(serializers.ModelSerializer):
    type = LabeledChoiceField(choices=TicketType.choices, read_only=True, label=_('Type'))
    approval_level = LabeledChoiceField(
        choices=TicketLevel.choices, read_only=True, label=_('Approve level')
    )
    cc_users = ObjectRelatedField(
        many=True, read_only=True, attrs=('id', 'name', 'username'), label=_('CC users')
    )

    class Meta:
        model = TicketFlow
        fields = ['id', 'name', 'type', 'approval_level', 'cc_users']
