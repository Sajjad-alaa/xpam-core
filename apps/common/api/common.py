# -*- coding: utf-8 -*-
#
import uuid

from django.core.cache import cache
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework.views import APIView

from common.const import (
    COUNTRY_CALLING_CODES,
    KEY_CACHE_RESOURCE_IDS,
    RESOURCE_IDS_CACHE_TIMEOUT,
)
from common.permissions import IsValidUser
from common.utils import get_logger
from common.views.http import HttpResponseTemporaryRedirect

__all__ = [
    'ResourcesIDCacheApi', 'CountryListApi'
]

logger = get_logger(__file__)


class ResourcesIDCacheApi(APIView):
    permission_classes = (IsValidUser,)

    def post(self, request, *args, **kwargs):
        spm = str(uuid.uuid4())
        resources = request.data.get('resources')
        if resources is not None:
            cache_key = KEY_CACHE_RESOURCE_IDS.format(spm)
            cache.set(cache_key, resources, RESOURCE_IDS_CACHE_TIMEOUT)
        return Response({'spm': spm})


class CountryListApi(APIView):
    permission_classes = (IsValidUser,)

    def get(self, request, *args, **kwargs):
        return Response(COUNTRY_CALLING_CODES)


@csrf_exempt
def redirect_plural_name_api(request, *args, **kwargs):
    resource = kwargs.get("resource", "")
    org_full_path = request.get_full_path()
    full_path = org_full_path.replace(resource, resource + "s", 1)
    logger.debug("Redirect {} => {}".format(org_full_path, full_path))
    return HttpResponseTemporaryRedirect(full_path)
