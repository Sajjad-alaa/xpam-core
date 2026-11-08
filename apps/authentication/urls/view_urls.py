# coding:utf-8
#

from django.db.transaction import non_atomic_requests
from django.urls import path, include


from users import views as users_view
from .. import views

app_name = 'authentication'

urlpatterns = [
    # login
    path('login/', non_atomic_requests(views.UserLoginView.as_view()), name='login'),
    path('login/mfa/', views.UserLoginMFAView.as_view(), name='login-mfa'),
    path('login/wait-confirm/', views.UserLoginWaitConfirmView.as_view(), name='login-wait-confirm'),
    path('login/mfa/face/capture/', views.UserLoginMFAFaceView.as_view(), name='login-face-capture'),
    path('login/guard/', views.UserLoginGuardView.as_view(), name='login-guard'),
    path('logout/', views.UserLogoutView.as_view(), name='logout'),

    # 原来在users中的
    path('password/forget/previewing/', users_view.UserForgotPasswordPreviewingView.as_view(),
         name='forgot-previewing'),
    path('password/forgot/', users_view.UserForgotPasswordView.as_view(), name='forgot-password'),
    path('password/reset/', users_view.UserResetPasswordView.as_view(), name='reset-password'),
    path('password/verify/', users_view.UserVerifyPasswordView.as_view(), name='user-verify-password'),


    # Profile
    path('profile/mfa/', users_view.MFASettingView.as_view(), name='user-mfa-setting'),
    path('profile/pubkey/generate/', users_view.UserPublicKeyGenerateView.as_view(), name='user-pubkey-generate'),

    # OTP Setting
    path('profile/otp/enable/start/', users_view.UserOtpEnableStartView.as_view(), name='user-otp-enable-start'),
    path('profile/otp/enable/install-app/', users_view.UserOtpEnableInstallAppView.as_view(),
         name='user-otp-enable-install-app'),
    path('profile/otp/enable/bind/', users_view.UserOtpEnableBindView.as_view(), name='user-otp-enable-bind'),
    path('profile/otp/disable/', users_view.UserOtpDisableView.as_view(),
         name='user-otp-disable'),

    path('profile/face/enable/', users_view.UserFaceEnableView.as_view(), name='user-face-enable'),
    path('profile/face/disable/', users_view.UserFaceDisableView.as_view(), name='user-face-disable'),
    # other authentication protocol
    path('cas/', include(('authentication.backends.cas.urls', 'authentication'), namespace='cas')),
    path('openid/', include(('authentication.backends.oidc.urls', 'authentication'), namespace='openid')),
    path('saml2/', include(('authentication.backends.saml2.urls', 'authentication'), namespace='saml2')),
    path('oauth2/', include(('authentication.backends.oauth2.urls', 'authentication'), namespace='oauth2')),

    path('captcha/', include('captcha.urls')),

    path('oauth2-provider/', include(('authentication.backends.oauth2_provider.urls', 'authentication'), namespace='oauth2-provider')),

]
