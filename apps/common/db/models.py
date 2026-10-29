"""
此文件作为 `django.db.models` 的 shortcut

这样做的优点与缺点为：
优点：
    - 包命名都统一为 `models`
    - 用户在使用的时候只导入本文件即可
缺点：
    - 此文件中添加代码的时候，注意不要跟 `django.db.models` 中的命名冲突
"""

import uuid

from django.db import models
from django.db.models import CASCADE
from django.utils.translation import gettext_lazy as _

from ..const.signals import OP_LOG_SKIP_SIGNAL


class ChoicesMixin:
    _value2label_map_: dict

    @classmethod
    def get_label(cls, value: (str, int)):
        return cls._value2label_map_[value]


class BaseCreateUpdateModel(models.Model):
    created_by = models.CharField(max_length=128, null=True, blank=True, verbose_name=_('Created by'))
    updated_by = models.CharField(max_length=128, null=True, blank=True, verbose_name=_('Updated by'))
    date_created = models.DateTimeField(auto_now_add=True, null=True, blank=True, verbose_name=_('Date created'))
    date_updated = models.DateTimeField(auto_now=True, verbose_name=_('Date updated'))
    comment = models.TextField(default='', blank=True, verbose_name=_('Comment'))

    class Meta:
        abstract = True


class JMSBaseModel(BaseCreateUpdateModel):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True)

    class Meta:
        abstract = True

    def __str__(self):
        return str(self.id)


def CASCADE_SIGNAL_SKIP(collector, field, sub_objs, using):
    # 级联删除时，操作日志标记不保存，以免用户混淆
    try:
        for obj in sub_objs:
            setattr(obj, OP_LOG_SKIP_SIGNAL, True)
    except:
        pass

    CASCADE(collector, field, sub_objs, using)
