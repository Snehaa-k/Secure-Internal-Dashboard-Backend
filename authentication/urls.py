from django.urls import path
from .views import (
    RegisterOptionsView, RegisterVerifyView,
    LoginOptionsView, LoginVerifyView,
    ValidateTokenView
)

urlpatterns = [
    path('register/options', RegisterOptionsView.as_view(), name='register-options'),
    path('register/verify', RegisterVerifyView.as_view(), name='register-verify'),
    path('login/options', LoginOptionsView.as_view(), name='login-options'),
    path('login/verify', LoginVerifyView.as_view(), name='login-verify'),
    path('validate', ValidateTokenView.as_view(), name='validate-token'),
]