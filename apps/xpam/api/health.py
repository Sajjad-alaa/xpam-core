import secrets
import time

from django.conf import settings
from django.core.cache import cache
from django.http.response import HttpResponse
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from terminal.utils import ComponentsPrometheusMetricsUtil
from users.models import User


class HealthApiMixin(APIView):
    pass


class HealthCheckView(HealthApiMixin):
    permission_classes = (AllowAny,)
    _cache_until = 0.0
    _cached_data = None
    _cached_code = 200

    @staticmethod
    def get_db_status():
        t1 = time.time()
        try:
            ok = User.objects.first() is not None
            t2 = time.time()
            return ok, round(t2 - t1, 4)
        except Exception:
            return False, 0

    @staticmethod
    def get_redis_status():
        key = 'HEALTH_CHECK'

        t1 = time.time()
        try:
            value = '1'
            cache.set(key, '1', 10)
            got = cache.get(key)
            t2 = time.time()

            if value == got:
                return True, round(t2 - t1, 4)
            return False, 0
        except Exception:
            return False, 0

    def get(self, request):
        now = time.monotonic()
        if self._cached_data is not None and now < self._cache_until:
            # a copy: the timing middleware adds keys to response.data, which must not touch the shared cache
            return Response(dict(self._cached_data), status=self._cached_code)
        redis_status, _redis_time = self.get_redis_status()
        db_status, _db_time = self.get_db_status()
        ok = all([redis_status, db_status])
        data = {
            'status': ok,
            'db_status': db_status,
            'redis_status': redis_status,
        }
        code = 200 if ok else 503
        HealthCheckView._cached_data = data
        HealthCheckView._cached_code = code
        HealthCheckView._cache_until = now + 2.0
        return Response(dict(data), status=code)


class PrometheusMetricsApi(HealthApiMixin):
    permission_classes = (AllowAny,)

    def get(self, request, *args, **kwargs):
        expected_token = str(settings.PROMETHEUS_METRICS_TOKEN or '')
        token = request.query_params.get('token', '')
        if not expected_token or not secrets.compare_digest(token, expected_token):
            return HttpResponse(status=403)

        util = ComponentsPrometheusMetricsUtil()
        metrics_text = util.get_prometheus_metrics_text()
        return HttpResponse(metrics_text, content_type='text/plain; version=0.0.4; charset=utf-8')
