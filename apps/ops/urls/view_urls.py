# ~*~ coding: utf-8 ~*~
from __future__ import unicode_literals
from django.urls import path

from .. import views

__all__ = ["urlpatterns"]

app_name = "ops"

urlpatterns = [
    # Resource Task url
    path('worker/task/<uuid:pk>/log/', views.CeleryTaskLogView.as_view(), name='worker-task-log'),
    # Address used before the rename; old links and audit entries keep working
    path('celery/task/<uuid:pk>/log/', views.CeleryTaskLogView.as_view(), name='celery-task-log'),
]