from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    RegistrationView,
    UserViewSet,
    LoginView,
    PasswordResetView,
    EmailVerificationView
)

router = DefaultRouter()
router.register(r'me', UserViewSet, basename='me')

urlpatterns = [
    path('register/', RegistrationView.as_view(), name='register'),

    path('login/', LoginView.as_view(), name='login'),

    path('token/refresh', TokenRefreshView.as_view(), name='token_refresh'),

    path('verify-email/', EmailVerificationView.as_view(), name='verify_email'),

    path('reset-password/', PasswordResetView.as_view(), name='reset_password'),

    path('', include(router.urls))
]
