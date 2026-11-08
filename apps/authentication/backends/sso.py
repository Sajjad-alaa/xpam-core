from django.conf import settings

from .base import JMSBaseAuthBackend


class SSOAuthentication(JMSBaseAuthBackend):
    @staticmethod
    def is_enabled():
        return settings.AUTH_SSO

    def authenticate(self):
        pass


class CustomSSOAuthentication(JMSBaseAuthBackend):
    @staticmethod
    def is_enabled():
        return settings.AUTH_CUSTOM_SSO

    def authenticate(self):
        pass







class AuthorizationTokenAuthentication(JMSBaseAuthBackend):
    def authenticate(self):
        pass
