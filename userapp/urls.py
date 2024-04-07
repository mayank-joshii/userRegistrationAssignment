# urls.py
# urls.py

from django.urls import path
from userapp.views import (
    UserRegistrationAPIView, UserLoginAPIView, TokenRefreshAPIView,
    VerifyEmailAPIView, ForgotPasswordAPIView, ResetPasswordAPIView
)

urlpatterns = [
    path('register/', UserRegistrationAPIView.as_view(), name='user-registration'),
    path('login/', UserLoginAPIView.as_view(), name='user-login'),
    path('token/refresh/', TokenRefreshAPIView.as_view(), name='token-refresh'),
    path('verify-email/', VerifyEmailAPIView.as_view(), name='verify-email'),
    path('forgot-password/', ForgotPasswordAPIView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordAPIView.as_view(), name='reset-password'),
]
