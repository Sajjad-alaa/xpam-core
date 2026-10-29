# -*- coding: utf-8 -*-
#
from datetime import datetime

from rest_framework import generics
from rest_framework.response import Response

from acls.models import CommandFilterACL, CommandGroup
from common.api import JMSBulkModelViewSet
from common.utils import get_logger
from terminal.backends import get_command_storage
from terminal.const import RiskLevelChoices
from terminal.exceptions import StorageInvalid
from terminal.filters import CommandFilter
from terminal.models import CommandStorage, Session, Command
from terminal.notifications import CommandAlertMessage, CommandWarningMessage
from terminal.serializers import (
    SessionCommandSerializer, InsecureCommandAlertSerializer
)

logger = get_logger(__name__)
__all__ = ['CommandViewSet', 'InsecureCommandAlertAPI']


class CommandViewSet(JMSBulkModelViewSet):
    """接受app发送来的command log, 格式如下
    {
        "user": "admin",
        "asset": "localhost",
        "account": "web",
        "session": "xxxxxx",
        "input": "whoami",
        "output": "d2hvbWFp",  # base64.b64encode(s)
        "timestamp": 1485238673.0
    }

    """
    command_store = get_command_storage()
    serializer_class = SessionCommandSerializer
    filterset_class = CommandFilter
    model = Command
    search_fields = ('input',)
    ordering_fields = ('timestamp', 'risk_level')

    def merge_all_storage_list(self, request, *args, **kwargs):
        merged_commands = []

        storages = CommandStorage.objects.all()
        for storage in storages:
            if not storage.is_valid():
                continue

            qs = storage.get_command_queryset()
            commands = self.filter_queryset(qs)
            merged_commands.extend(commands[:])  # ES 默认只取 10 条数据
        order = self.request.query_params.get('order', None)
        if order == 'timestamp':
            merged_commands.sort(key=lambda command: command.timestamp)
        else:
            merged_commands.sort(key=lambda command: command.timestamp, reverse=True)
        page = self.paginate_queryset(merged_commands)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(merged_commands, many=True)
        return Response(serializer.data)

    def list(self, request, *args, **kwargs):
        command_storage_id = self.request.query_params.get('command_storage_id')
        session_id = self.request.query_params.get('session_id')

        if session_id and not command_storage_id:
            # 会话里的命令列表肯定会提供 session_id，这里防止 merge 的时候取全量的数据
            return self.merge_all_storage_list(request, *args, **kwargs)
        queryset = self.get_queryset()
        queryset = self.filter_queryset(queryset)

        page = self.paginate_queryset(queryset)
        if page is not None:
            page = self.load_remote_addr(page)
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        # 适配像 ES 这种没有指定分页只返回少量数据的情况
        queryset = queryset[:]

        queryset = self.load_remote_addr(queryset)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def load_remote_addr(self, queryset):
        commands = list(queryset)
        session_ids = {command.session for command in commands}
        sessions = Session.objects.filter(id__in=session_ids).values_list('id', 'remote_addr')
        session_addr_map = {str(i): addr for i, addr in sessions}
        for command in commands:
            command.remote_addr = session_addr_map.get(command.session, '')
        return commands

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return Command.objects.none()

        command_storage_id = self.request.query_params.get('command_storage_id')
        if not command_storage_id:
            storage = CommandStorage.default()
            if not storage:
                return Command.objects.none()
        else:
            storage = CommandStorage.objects.get(id=command_storage_id)
        if not storage.is_valid():
            raise StorageInvalid
        else:
            qs = storage.get_command_queryset()
        return qs

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, many=True)
        if serializer.is_valid():
            ok = self.command_store.bulk_save(serializer.validated_data)
            if ok:
                return Response("ok", status=201)
            else:
                return Response("Save error", status=500)
        else:
            msg = "Command not valid: {}".format(serializer.errors)
            logger.error(msg)
            return Response({"msg": msg}, status=401)


class InsecureCommandAlertAPI(generics.CreateAPIView):
    serializer_class = InsecureCommandAlertSerializer
    rbac_perms = {
        'POST': 'terminal.add_command'
    }

    def post(self, request, *args, **kwargs):
        serializer = InsecureCommandAlertSerializer(data=request.data, many=True)
        serializer.is_valid(raise_exception=True)
        commands = serializer.validated_data
        session_ids, acl_ids, cmd_group_ids = set(), set(), set()
        for command in commands:
            session_ids.add(command.get('session'))
            acl_ids.add(command.get('cmd_filter_acl'))
            cmd_group_ids.add(command.get('cmd_group'))

        sessions = Session.objects.filter(id__in=session_ids).only(
            'id', 'org_id', 'asset', 'asset_id', 'user', 'user_id', 'account', 'account_id'
        )
        session_mapper = {str(i.id): i for i in sessions}
        acls = CommandFilterACL.objects.filter(id__in=acl_ids).only('id', 'name', 'reviewers')
        acl_mapper = {str(i.id): i for i in acls}
        cmd_groups = CommandGroup.objects.filter(id__in=cmd_group_ids).only('id', 'name')
        cmd_group_mapper = {str(i.id): i for i in cmd_groups}

        for command in commands:
            command['_time'] = datetime.fromtimestamp(command['timestamp'])
            cmd_acl = acl_mapper.get(command['cmd_filter_acl'])
            command['_cmd_filter_acl'] = cmd_acl
            cmd_group = cmd_group_mapper.get(command['cmd_group'])
            command['_cmd_group'] = cmd_group
            session = session_mapper.get(command['session'])
            risk_level = command.get('risk_level')

            if session:
                command.update({
                    '_account': session.account,
                    '_org_name': session.org.name,
                    '_protocol': session.protocol,
                    '_remote_addr': session.remote_addr,
                    '_login_from': session.get_login_from_display(),
                })

            if risk_level in [RiskLevelChoices.reject, RiskLevelChoices.review_reject]:
                CommandAlertMessage(command).publish_async()
            elif risk_level in [RiskLevelChoices.warning]:
                for reviewer in cmd_acl.reviewers.all():
                    CommandWarningMessage(reviewer, command).publish_async()
            else:
                logger.info(f'Risk level ignore: {RiskLevelChoices.get_label(risk_level)}({risk_level})')

        return Response({'msg': 'ok'})
