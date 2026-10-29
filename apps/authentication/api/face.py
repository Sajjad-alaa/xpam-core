from django.conf import settings
from django.core.cache import cache
from django.utils.translation import gettext as _
from rest_framework.exceptions import NotFound
from rest_framework.generics import CreateAPIView, RetrieveAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.serializers import ValidationError

from common.permissions import IsServiceAccount
from common.utils import get_logger, get_object_or_none
from orgs.utils import tmp_to_root_org
from terminal.api.session.task import create_sessions_tasks
from terminal.const import TerminalType
from users import face_sface
from users.models import User
from .. import serializers
from ..const import (
    FACE_CONTEXT_CACHE_KEY_PREFIX,
    FACE_CONTEXT_CACHE_TTL,
    FACE_MONITOR_CONTEXT_CACHE_TTL,
    FACE_SESSION_KEY,
    FaceMonitorActionChoices,
)
from ..mixins import AuthMixin
from ..models import ConnectionToken
from ..serializers.face import (
    FaceEngineCompareSerializer, FaceMonitorCallbackSerializer, FaceMonitorContextSerializer
)

logger = get_logger(__name__)

# Most comparisons the engine may ask for with one capture token
FACE_ENGINE_COMPARE_LIMIT = 40
# Faces that did not match a user: past this many in FACE_ENGINE_FAIL_WINDOW seconds, that user's face sign-in waits
# (someone with the password trying photo after photo gets no more tries meanwhile)
FACE_ENGINE_FAIL_LIMIT = 30
FACE_ENGINE_FAIL_WINDOW = 15 * 60


class IsFaceEngine(IsServiceAccount):
    """The face engine's own service account: not the SSH/RDP service, the AI or another component."""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        terminal = getattr(request.user, 'terminal', None)
        return bool(terminal and terminal.type == TerminalType.facelive and not terminal.is_deleted)

__all__ = [
    'FaceCallbackApi',
    'FaceContextApi',
    'FaceEngineContextApi',
    'FaceEngineCompareApi',
    'FaceMonitorContext',
    'FaceMonitorContextApi',
    'FaceMonitorCallbackApi'
]


class FaceCallbackApi(AuthMixin, CreateAPIView):
    permission_classes = (IsFaceEngine,)
    serializer_class = serializers.FaceCallbackSerializer

    def perform_create(self, serializer):
        token = serializer.validated_data.get('token')
        context = self._get_context_from_cache(token)
        if context.get('is_finished'):
            # (a result is final: a second callback must not turn a failure into a success)
            raise ValidationError({'error': "the face capture is already finished"})

        if not serializer.validated_data.get('success', False):
            self._update_context_with_error(
                context,
                serializer.validated_data.get('error_message', 'Unknown error')
            )
            return Response(status=200)

        face_code = serializer.validated_data.get('face_code')
        if not face_code:
            self._update_context_with_error(context, "missing field 'face_code'")
            raise ValidationError({'error': "missing field 'face_code'"})
        try:
            self._handle_success(context, face_code)
        except Exception as e:
            self._update_context_with_error(context, str(e))
        return Response(status=200)

    @staticmethod
    def get_face_cache_key(token):
        return f"{FACE_CONTEXT_CACHE_KEY_PREFIX}_{token}"

    def _get_context_from_cache(self, token):
        cache_key = self.get_face_cache_key(token)
        context = cache.get(cache_key)
        if not context:
            raise ValidationError({'error': "token not exists or expired"})
        return context

    def _update_context_with_error(self, context, error_message):
        context.update({
            'is_finished': True,
            'success': False,
            'error_message': error_message,
        })
        self._update_cache(context)

    def _update_cache(self, context):
        cache_key = self.get_face_cache_key(context['token'])
        cache.set(cache_key, context, FACE_CONTEXT_CACHE_TTL)

    def _handle_success(self, context, face_code):
        context.update({
            'is_finished': True,
            'success': True,
            'face_code': face_code
        })
        action = context.get('action', None)
        if action == 'login_asset':
            user_id = context.get('user_id')
            user = User.objects.get(id=user_id)

            if user.check_face(face_code):
                with tmp_to_root_org():
                    connection_token_id = context.get('connection_token_id')
                    token = ConnectionToken.objects.filter(id=connection_token_id).first()
                    token.is_active = True
                    token.save(update_fields=['is_active'])
            else:
                context.update({
                    'success': False,
                    'error_message': _('Facial comparison failed')
                })
        self._update_cache(context)


class FaceContextApi(AuthMixin, RetrieveAPIView, CreateAPIView):
    permission_classes = (AllowAny,)
    face_token_session_key = FACE_SESSION_KEY

    @staticmethod
    def get_face_cache_key(token):
        return f"{FACE_CONTEXT_CACHE_KEY_PREFIX}_{token}"

    def new_face_context(self):
        return self.create_face_verify_context()

    def post(self, request, *args, **kwargs):
        token = self.new_face_context()
        return Response({'token': token})

    def get(self, request, *args, **kwargs):
        session_token = self.request.session.get(self.face_token_session_key)
        requested_token = self.request.query_params.get('token')
        if requested_token and requested_token != session_token:
            raise NotFound({'error': "Token does not belong to the current face capture."})
        token = requested_token or session_token

        cache_key = self.get_face_cache_key(token)
        context = cache.get(cache_key)
        if not context:
            raise NotFound({'error': "Token does not exist or has expired."})

        return Response({
            "is_finished": context.get('is_finished', False),
            "success": context.get('success', False),
            "error_message": _(context.get("error_message", ''))
        })


class FaceEngineMixin:
    """What the facelive engine (a service account) may ask about a capture token."""

    @staticmethod
    def fail_key(user):
        return f"FACE_ENGINE_FAILS_{user.id}"

    def too_many_failures(self, user):
        return (cache.get(self.fail_key(user)) or 0) >= FACE_ENGINE_FAIL_LIMIT

    def count_failure(self, user):
        key = self.fail_key(user)
        cache.add(key, 0, FACE_ENGINE_FAIL_WINDOW)
        try:
            count = cache.incr(key)
        except ValueError:
            count = 1
        if count == FACE_ENGINE_FAIL_LIMIT:
            logger.warning('Face sign-in of user %s paused: %s faces did not match', user.username, count)

    @staticmethod
    def get_open_context(token):
        """The capture context of this token, or None when it is unknown, finished or has no usable user."""
        context = cache.get(f"{FACE_CONTEXT_CACHE_KEY_PREFIX}_{token}")
        if not context or context.get('is_finished'):
            return None, None
        user_id = context.get('user_id')
        user = User.objects.filter(id=user_id, is_active=True).first() if user_id else None
        if not user:
            return None, None
        return context, user


class FaceEngineContextApi(FaceEngineMixin, RetrieveAPIView):
    """The engine asks, before it streams anything, what this capture token is for.

    Answers only: is the token usable, enrol or authenticate, the user's display name and the threshold.
    No face data is returned.
    """
    permission_classes = (IsFaceEngine,)

    def retrieve(self, request, *args, **kwargs):
        token = request.query_params.get('token', '')
        context, user = self.get_open_context(token)
        if not context:
            raise NotFound({'error': 'Token does not exist, has expired or is finished.'})
        if user.is_face_code_set:
            if self.too_many_failures(user):
                raise NotFound({'error': 'Too many faces did not match. Try again later.'})
            mode = 'auth'
        elif context.get('authenticated'):
            mode = 'enroll'
        else:
            # A login that is still waiting for its second factor must not bind a new face
            raise NotFound({'error': 'Face enrollment needs a signed-in user.'})
        return Response({
            'valid': True,
            'mode': mode,
            'action': context.get('action', ''),
            'target_name': user.name or user.username,
            'threshold': settings.FACE_RECOGNITION_COSINE_THRESHOLD,
        })


class FaceEngineCompareApi(FaceEngineMixin, CreateAPIView):
    """The engine asks if a face code is the user of this capture token (the stored face never leaves core).

    The answer is yes or no only: a similarity score would tell someone at the camera how close a photo or a mask
    comes to the stored face, and help them improve it.
    """
    permission_classes = (IsFaceEngine,)
    serializer_class = FaceEngineCompareSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data['token']
        face_code = serializer.validated_data['face_code']
        context, user = self.get_open_context(token)
        if not context or not user.is_face_code_set:
            raise NotFound({'error': 'Token does not exist, has expired or has no enrolled face.'})
        counter_key = f"FACE_ENGINE_COMPARE_{token}"
        cache.add(counter_key, 0, FACE_CONTEXT_CACHE_TTL)
        try:
            count = cache.incr(counter_key)
        except ValueError:
            count = 1
        if count > FACE_ENGINE_COMPARE_LIMIT or self.too_many_failures(user):
            raise ValidationError({'error': 'Too many comparisons for this capture.'})
        matched = bool(face_sface.similarity(str(user.face_vector), face_code) is not None
                       and user.check_face(face_code))
        if not matched:
            self.count_failure(user)
        return Response({'matched': matched})


class FaceMonitorContext:
    def __init__(self, token, user_id, session_ids=None):
        self.token = token
        self.user_id = user_id
        if session_ids is None:
            self.session_ids = []
        else:
            self.session_ids = session_ids

    @classmethod
    def get_cache_key(cls, token):
        return 'FACE_MONITOR_CONTEXT_{}'.format(token)

    @classmethod
    def get_or_create_context(cls, token, user_id):
        context = cls.get(token)
        if not context:
            context = FaceMonitorContext(token=token,
                                         user_id=user_id)
            context.save()
        return context

    def add_session(self, session_id):
        self.session_ids.append(session_id)
        self.save()

    @classmethod
    def get(cls, token):
        cache_key = cls.get_cache_key(token)
        return cache.get(cache_key, None)

    def save(self):
        cache_key = self.get_cache_key(self.token)
        cache.set(cache_key, self, FACE_MONITOR_CONTEXT_CACHE_TTL)

    def close(self):
        self.terminal_sessions()
        self._destroy()

    def _destroy(self):
        cache_key = self.get_cache_key(self.token)
        cache.delete(cache_key)

    def pause_sessions(self):
        self._send_task('lock_session')

    def resume_sessions(self):
        self._send_task('unlock_session')

    def terminal_sessions(self):
        self._send_task("kill_session")

    def _send_task(self, task_name):
        create_sessions_tasks(self.session_ids, 'facelive', task_name=task_name)


class FaceMonitorContextApi(CreateAPIView):
    permission_classes = (IsServiceAccount,)
    serializer_class = FaceMonitorContextSerializer

    def perform_create(self, serializer):
        face_monitor_token = serializer.validated_data.get('face_monitor_token')
        session_id = serializer.validated_data.get('session_id')

        context = FaceMonitorContext.get(face_monitor_token)
        context.add_session(session_id)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(status=201)


class FaceMonitorCallbackApi(CreateAPIView):
    # (pauses and resumes users' sessions: the face engine only)
    permission_classes = (IsFaceEngine,)
    serializer_class = FaceMonitorCallbackSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data.get('token')

        context = FaceMonitorContext.get(token=token)
        is_finished = serializer.validated_data.get('is_finished')
        if is_finished:
            context.close()
            return Response(status=200)

        action = serializer.validated_data.get('action')
        if action == FaceMonitorActionChoices.Verify:
            user = get_object_or_none(User, pk=context.user_id)
            face_codes = serializer.validated_data.get('face_codes')

            if not user:
                context.save()
                return Response(data={'msg': 'user {} not found'
                                .format(context.user_id)}, status=400)

            if not face_codes or not self._check_face_codes(face_codes, user):
                context.save()
                return Response(data={'msg': 'face codes not matched'}, status=400)

        if action == FaceMonitorActionChoices.Pause:
            context.pause_sessions()
        if action == FaceMonitorActionChoices.Resume:
            context.resume_sessions()

        context.save()
        return Response(status=200)

    @staticmethod
    def _check_face_codes(face_codes, user):
        matched = False
        for face_code in face_codes:
            # (the thresholds come from the settings: FACE_RECOGNITION_*_THRESHOLD)
            matched = user.check_face(face_code)
            if matched:
                break
        return matched
