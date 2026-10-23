import uuid

from django.db import transaction
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from common.utils import is_uuid
from orgs.models import Organization
from orgs.utils import current_org, get_current_org, tmp_to_org, tmp_to_root_org
from reports.models import CustomDashboard, DASHBOARD_WIDGET_IDS
from users.models import User, UserGroup

__all__ = ['CustomDashboardViewSet']

ALLOWED_DAYS = {1, 7, 30}
ALLOWED_REFRESH = {0, 15, 60, 300}
ALLOWED_SPANS = {6, 8, 12, 16, 24}

WIDGET_CATALOG = [
    {
        'id': 'protection_status',
        'category': 'console',
        'title': _('HA & Vault Protection Status'),
        'description': _('Live High Availability cluster health, Vault reachability, and secret storage status.'),
        'default_span': 24,
        'perm': 'settings.view_setting',
    },
    {
        'id': 'console_realtime',
        'category': 'console',
        'title': _('Real-Time Connections & Online Users'),
        'description': _('Active sessions right now, currently connected users, and failed connections today.'),
        'default_span': 12,
        'perm': 'rbac.view_console',
    },
    {
        'id': 'console_data_summary',
        'category': 'console',
        'title': _('Users & Assets Active Ratio'),
        'description': _('Total users and assets with active vs. inactive rings and weekly growth.'),
        'default_span': 12,
        'perm': 'rbac.view_console',
    },
    {
        'id': 'console_user_asset_activity',
        'category': 'console',
        'title': _('User & Asset Activity Trend'),
        'description': _('Daily login trend across active users, active assets, and total sessions.'),
        'default_span': 12,
        'perm': 'rbac.view_console',
    },
    {
        'id': 'console_asset_proportion',
        'category': 'console',
        'title': _('Asset Inventory by Platform Type'),
        'description': _('Breakdown of hosts, databases, network devices, cloud, and web assets.'),
        'default_span': 12,
        'perm': 'rbac.view_console',
    },
    {
        'id': 'console_rank_summary',
        'category': 'console',
        'title': _('Top 10 Active Users & Visited Assets'),
        'description': _('Leaderboard of the most active users and most frequently accessed assets.'),
        'default_span': 24,
        'perm': 'rbac.view_console',
    },
    {
        'id': 'jit_zsp_overview',
        'category': 'jit',
        'title': _('Zero Standing Privilege (ZSP) & JIT Posture'),
        'description': _('ZSP score ring, live JIT accounts, auto-approval rate, median wait time, and 14-day trend.'),
        'default_span': 24,
        'perm': 'accounts.view_jitaccount',
    },
    {
        'id': 'jit_standing_converter',
        'category': 'jit',
        'title': _('Standing Access to JIT Conversion Queue'),
        'description': _('Permissions that still expose standing accounts and can be converted to JIT in one click.'),
        'default_span': 24,
        'perm': 'accounts.view_jitaccount',
    },
    {
        'id': 'pam_data_summary',
        'category': 'pam',
        'title': _('PAM Account Inventory KPIs'),
        'description': _('Total accounts, discovered accounts, templates, and privileged account counts.'),
        'default_span': 14,
        'perm': 'rbac.view_pam',
    },
    {
        'id': 'pam_mission_summary',
        'category': 'pam',
        'title': _('PAM Automation & Task Status'),
        'description': _('Status of account discovery, secret rotation, backup, and push automations.'),
        'default_span': 10,
        'perm': 'rbac.view_pam',
    },
    {
        'id': 'pam_secret_rotation',
        'category': 'pam',
        'title': _('Secret Rotation Execution Trend'),
        'description': _('Daily success vs. failure metrics for automated password and key rotations.'),
        'default_span': 14,
        'perm': 'accounts.view_changesecretautomation',
    },
    {
        'id': 'pam_risk_summary',
        'category': 'pam',
        'title': _('Credential Risk & Weak Password Radar'),
        'description': _('Weak passwords, leaked secrets, shared keys, and long-unrotated credentials.'),
        'default_span': 10,
        'perm': 'rbac.view_pam',
    },
    {
        'id': 'pam_account_proportion',
        'category': 'pam',
        'title': _('Managed Accounts by Asset Type'),
        'description': _('Distribution of managed accounts across Linux, Windows, databases, and devices.'),
        'default_span': 24,
        'perm': 'rbac.view_pam',
    },
    {
        'id': 'audit_card_summary',
        'category': 'audit',
        'title': _('Security Audit & Command KPIs'),
        'description': _('Logins, operations, password changes, executed commands, blocked high-risk commands, and file transfers.'),
        'default_span': 24,
        'perm': 'rbac.view_audit',
    },
    {
        'id': 'audit_session_charts',
        'category': 'audit',
        'title': _('Active Sessions & Risk Command Breakdown'),
        'description': _('Online vs. historical sessions and command risk distribution for the selected time window.'),
        'default_span': 24,
        'perm': 'rbac.view_audit',
    },
    {
        'id': 'audit_trend_summary',
        'category': 'audit',
        'title': _('Audit Session & Login Timeline'),
        'description': _('Multi-day timeline of audited sessions and user logins.'),
        'default_span': 24,
        'perm': 'rbac.view_audit',
    },
]

WIDGET_BY_ID = {w['id']: w for w in WIDGET_CATALOG}

STARTER_TEMPLATES = [
    {
        'id': 'soc_live',
        'name': _('SOC Live Operations Wall'),
        'description': _('Real-time active sessions, blocked high-risk commands, JIT activity, and top active users/assets.'),
        'icon': 'audit',
        'scope': 'all',
        'days': 7,
        'refresh_seconds': 15,
        'widgets': [
            {'widget': 'console_realtime', 'span': 12},
            {'widget': 'console_data_summary', 'span': 12},
            {'widget': 'audit_card_summary', 'span': 24},
            {'widget': 'audit_session_charts', 'span': 24},
            {'widget': 'console_rank_summary', 'span': 24},
            {'widget': 'audit_trend_summary', 'span': 24},
        ],
    },
    {
        'id': 'jit_zsp',
        'name': _('Zero Standing Privilege & JIT Command Center'),
        'description': _('Track ZSP posture score, live ephemeral accounts, approval SLA velocity, and standing-to-JIT conversion.'),
        'icon': 'key',
        'scope': 'all',
        'days': 7,
        'refresh_seconds': 60,
        'widgets': [
            {'widget': 'jit_zsp_overview', 'span': 24},
            {'widget': 'jit_standing_converter', 'span': 24},
            {'widget': 'console_realtime', 'span': 12},
            {'widget': 'protection_status', 'span': 12},
        ],
    },
    {
        'id': 'vault_pam',
        'name': _('Vault & Privileged Credential Hygiene'),
        'description': _('Monitor Vault health, secret rotation success, credential risks, and PAM automation coverage.'),
        'icon': 'pam',
        'scope': 'all',
        'days': 7,
        'refresh_seconds': 60,
        'widgets': [
            {'widget': 'protection_status', 'span': 24},
            {'widget': 'pam_data_summary', 'span': 14},
            {'widget': 'pam_mission_summary', 'span': 10},
            {'widget': 'pam_secret_rotation', 'span': 14},
            {'widget': 'pam_risk_summary', 'span': 10},
            {'widget': 'pam_account_proportion', 'span': 24},
        ],
    },
    {
        'id': 'executive',
        'name': _('Executive Security & Compliance Overview'),
        'description': _('High-level posture combining HA/Vault protection, ZSP score, PAM risk radar, and asset/user activity.'),
        'icon': 'dashboard',
        'scope': 'all',
        'days': 30,
        'refresh_seconds': 300,
        'widgets': [
            {'widget': 'protection_status', 'span': 24},
            {'widget': 'jit_zsp_overview', 'span': 24},
            {'widget': 'console_data_summary', 'span': 12},
            {'widget': 'pam_risk_summary', 'span': 12},
            {'widget': 'console_user_asset_activity', 'span': 12},
            {'widget': 'console_asset_proportion', 'span': 12},
        ],
    },
]

TEMPLATE_BY_ID = {t['id']: t for t in STARTER_TEMPLATES}


def can_manage(user, action='change'):
    """Role permissions (reports.add/change/delete_customdashboard): organization administrators have them;
    auditors and users only see the dashboards shared with them."""
    if not user or not user.is_authenticated:
        return False
    return bool(user.is_superuser or user.has_perm(f'reports.{action}_customdashboard'))


def normalize_layout(raw_layout, template_id=None):
    if not raw_layout and template_id in TEMPLATE_BY_ID:
        raw_layout = TEMPLATE_BY_ID[template_id]['widgets']
    if not isinstance(raw_layout, list):
        raise serializers.ValidationError(_('Layout must be a list of widgets'))
    cleaned = []
    for idx, item in enumerate(raw_layout[:30]):
        if isinstance(item, str):
            item = {'widget': item}
        if not isinstance(item, dict):
            continue
        widget_id = str(item.get('widget') or '').strip()
        if widget_id not in DASHBOARD_WIDGET_IDS:
            raise serializers.ValidationError(_('Unsupported widget: %s') % widget_id)
        default_span = WIDGET_BY_ID[widget_id]['default_span']
        try:
            span = int(item.get('span') or default_span)
        except (TypeError, ValueError):
            span = default_span
        if span not in ALLOWED_SPANS:
            span = default_span
        cleaned.append({
            'id': str(item.get('id') or f'{widget_id}_{idx + 1}_{uuid.uuid4().hex[:6]}'),
            'widget': widget_id,
            'span': span,
            'title': str(item.get('title') or '').strip()[:128],
        })
    return cleaned


class CustomDashboardSerializer(serializers.ModelSerializer):
    shared_users = serializers.ListField(
        child=serializers.UUIDField(), required=False, write_only=True
    )
    shared_groups = serializers.ListField(
        child=serializers.UUIDField(), required=False, write_only=True
    )
    shared_users_info = serializers.SerializerMethodField(read_only=True)
    shared_groups_info = serializers.SerializerMethodField(read_only=True)
    owner_name = serializers.SerializerMethodField(read_only=True)
    org_name = serializers.SerializerMethodField(read_only=True)
    can_edit = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = CustomDashboard
        fields = [
            'id', 'name', 'description', 'icon', 'scope', 'template', 'layout',
            'days', 'refresh_seconds', 'is_default', 'is_shared_all', 'sort_order',
            'owner', 'owner_name', 'org_id', 'org_name',
            'shared_users', 'shared_groups', 'shared_users_info', 'shared_groups_info',
            'can_edit', 'date_created', 'date_updated',
        ]
        read_only_fields = [
            'id', 'owner', 'owner_name', 'org_id', 'org_name',
            'shared_users_info', 'shared_groups_info', 'can_edit',
            'date_created', 'date_updated',
        ]

    @staticmethod
    def get_owner_name(obj):
        return str(obj.owner) if obj.owner else (obj.created_by or '')

    @staticmethod
    def get_org_name(obj):
        org = Organization.get_instance(obj.org_id)
        return str(org.name) if org else ''

    def get_can_edit(self, obj):
        request = self.context.get('request')
        user = getattr(request, 'user', None)
        return can_manage(user)

    @staticmethod
    def get_shared_users_info(obj):
        return [{'id': str(u.id), 'name': str(u)} for u in obj.shared_users.all()]

    @staticmethod
    def get_shared_groups_info(obj):
        return [{'id': str(g.id), 'name': str(g.name)} for g in obj.shared_groups.all()]

    def validate_days(self, value):
        try:
            v = int(value)
        except (TypeError, ValueError):
            raise serializers.ValidationError(_('Invalid days'))
        if v not in ALLOWED_DAYS:
            raise serializers.ValidationError(_('Days must be 1, 7, or 30'))
        return v

    def validate_refresh_seconds(self, value):
        try:
            v = int(value)
        except (TypeError, ValueError):
            raise serializers.ValidationError(_('Invalid refresh interval'))
        if v not in ALLOWED_REFRESH:
            raise serializers.ValidationError(_('Refresh seconds must be 0, 15, 60, or 300'))
        return v

    def validate(self, attrs):
        template_id = attrs.get('template') or (self.instance.template if self.instance else 'custom')
        if 'layout' in attrs or not self.instance:
            raw_layout = attrs.get('layout')
            attrs['layout'] = normalize_layout(raw_layout, template_id=template_id)
            if not attrs['layout']:
                raise serializers.ValidationError({'layout': _('Add at least one widget to the dashboard')})
        return attrs

    def _resolve_org_targets(self, org_id, user_ids, group_ids):
        org = Organization.get_instance(org_id) or current_org
        users = []
        groups = []
        if user_ids is not None:
            valid_users = User.get_org_users(org=org) if not org.is_root() else User.objects.all()
            users = list(valid_users.filter(id__in=user_ids))
        if group_ids is not None:
            with tmp_to_org(org):
                groups = list(UserGroup.objects.filter(id__in=group_ids))
        return users, groups

    @transaction.atomic
    def create(self, validated_data):
        user_ids = validated_data.pop('shared_users', None)
        group_ids = validated_data.pop('shared_groups', None)
        request = self.context.get('request')
        user = getattr(request, 'user', None)
        org_id = str(current_org.id)
        validated_data['org_id'] = org_id
        validated_data['owner'] = user
        if validated_data.get('is_default'):
            with tmp_to_root_org():
                CustomDashboard.objects.filter(org_id=org_id, is_default=True).update(is_default=False)
        instance = super().create(validated_data)
        users, groups = self._resolve_org_targets(org_id, user_ids, group_ids)
        if user_ids is not None:
            instance.shared_users.set(users)
        if group_ids is not None:
            instance.shared_groups.set(groups)
        return instance

    @transaction.atomic
    def update(self, instance, validated_data):
        user_ids = validated_data.pop('shared_users', None)
        group_ids = validated_data.pop('shared_groups', None)
        if validated_data.get('is_default'):
            with tmp_to_root_org():
                CustomDashboard.objects.filter(
                    org_id=instance.org_id, is_default=True
                ).exclude(id=instance.id).update(is_default=False)
        instance = super().update(instance, validated_data)
        users, groups = self._resolve_org_targets(instance.org_id, user_ids, group_ids)
        if user_ids is not None:
            instance.shared_users.set(users)
        if group_ids is not None:
            instance.shared_groups.set(groups)
        return instance

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['shared_users'] = [u['id'] for u in data['shared_users_info']]
        data['shared_groups'] = [g['id'] for g in data['shared_groups_info']]
        return data


class CustomDashboardViewSet(viewsets.ModelViewSet):
    """
    XPAM Multi-Dashboard & Custom Dashboard Builder API.
    - Strictly isolated per organization (Org A cannot see Org B's dashboards; only System Admin in Root org can see all).
    - Admins create dashboards and share them with specific users, specific user groups, or the whole organization.
    """
    serializer_class = CustomDashboardSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        scope = self.request.query_params.get('scope')
        # (the request's organization, read before switching to the root organization for the query)
        org = get_current_org()
        org_id, in_root = str(org.id), org.is_root()
        with tmp_to_root_org():
            qs = CustomDashboard.objects.select_related('owner').prefetch_related('shared_users', 'shared_groups')
            # Strict organization isolation: non-root orgs only ever see their own org_id.
            # Root org is only visible across orgs to a superuser.
            if in_root and user.is_superuser:
                org_filter = self.request.query_params.get('org_id')
                if org_filter and is_uuid(org_filter):
                    qs = qs.filter(org_id=str(org_filter))
            else:
                qs = qs.filter(org_id=org_id)

            if not can_manage(user, 'view'):
                qs = qs.filter(
                    Q(owner=user)
                    | Q(is_shared_all=True)
                    | Q(shared_users=user)
                    | Q(shared_groups__users=user)
                ).distinct()

            if scope in ('console', 'pam', 'audit'):
                qs = qs.filter(scope__in=['all', scope])

            return qs.order_by('-is_default', 'sort_order', 'name', '-date_created')

    def _require(self, request, action):
        if not can_manage(request.user, action):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied(_('Only an administrator can create or manage shared dashboards'))

    def create(self, request, *args, **kwargs):
        self._require(request, 'add')
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        self._require(request, 'change')
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        self._require(request, 'change')
        return super().partial_update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        self._require(request, 'delete')
        return super().destroy(request, *args, **kwargs)

    @action(methods=['get'], detail=False, url_path='catalog')
    def catalog(self, request, *args, **kwargs):
        from accounts.jit.policy import tickets_enabled
        jit_enabled = tickets_enabled()
        user = request.user
        widgets = []
        for w in WIDGET_CATALOG:
            if w['category'] == 'jit' and not jit_enabled:
                continue
            widgets.append({
                'id': w['id'],
                'category': w['category'],
                'title': str(w['title']),
                'description': str(w['description']),
                'default_span': w['default_span'],
                'allowed': bool(user.is_superuser or not w['perm'] or user.has_perm(w['perm'])),
            })
        templates = [
            {
                'id': t['id'],
                'name': str(t['name']),
                'description': str(t['description']),
                'icon': t['icon'],
                'scope': t['scope'],
                'days': t['days'],
                'refresh_seconds': t['refresh_seconds'],
                'widgets': [
                    item for item in t['widgets']
                    if jit_enabled or not str(item.get('widget', '')).startswith('jit_')
                ],
            }
            for t in STARTER_TEMPLATES
            if jit_enabled or t['id'] != 'jit_zsp'
        ]
        return Response({
            'can_manage': can_manage(user, 'add'),
            'org_id': str(current_org.id),
            'org_name': str(current_org.name),
            'widgets': widgets,
            'templates': templates,
        })

    @action(methods=['get'], detail=False, url_path='share-targets')
    def share_targets(self, request, *args, **kwargs):
        """Users and user groups of the current organization that a dashboard can be shared with."""
        self._require(request, 'change')
        search = (request.query_params.get('search') or '').strip()[:128]
        org = current_org
        users_qs = (
            User.get_org_users(org=org).filter(is_active=True)
            if not org.is_root()
            else User.objects.filter(is_active=True)
        )
        if search:
            users_qs = users_qs.filter(Q(name__icontains=search) | Q(username__icontains=search))
        with tmp_to_org(org):
            groups_qs = UserGroup.objects.all()
            if search:
                groups_qs = groups_qs.filter(name__icontains=search)
            groups = [{'id': str(g.id), 'name': g.name} for g in groups_qs.order_by('name')[:200]]
        users = [{'id': str(u.id), 'name': f'{u.name} ({u.username})'} for u in users_qs.order_by('name')[:300]]
        return Response({'users': users, 'groups': groups})

    @action(methods=['post'], detail=True, url_path='clone')
    def clone(self, request, *args, **kwargs):
        self._require(request, 'add')
        source = self.get_object()
        name = (request.data.get('name') or f'{source.name} (Copy)').strip()[:128]
        with transaction.atomic():
            cloned = CustomDashboard.objects.create(
                name=name,
                description=source.description,
                icon=source.icon,
                scope=source.scope,
                template=source.template,
                layout=normalize_layout(source.layout),
                days=source.days,
                refresh_seconds=source.refresh_seconds,
                is_default=False,
                is_shared_all=source.is_shared_all,
                sort_order=source.sort_order + 1,
                owner=request.user,
                org_id=str(current_org.id) if not current_org.is_root() else source.org_id,
            )
            cloned.shared_users.set(source.shared_users.all())
            cloned.shared_groups.set(source.shared_groups.all())
        serializer = self.get_serializer(cloned)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
