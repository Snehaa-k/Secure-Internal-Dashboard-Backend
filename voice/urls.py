from django.urls import path
from .views import (
    DialCallView,
    HangupCallView,
    CallStatusView,
    CallHistoryView,
    TwilioWebhookView,
    AccessTokenView
)

urlpatterns = [
    path('calls/dial/', DialCallView.as_view(), name='dial-call'),
    path('calls/<int:call_id>/hangup/', HangupCallView.as_view(), name='hangup-call'),
    path('calls/<int:call_id>/', CallStatusView.as_view(), name='call-status'),
    path('calls/history/', CallHistoryView.as_view(), name='call-history'),
    path('webhook/', TwilioWebhookView.as_view(), name='twilio-webhook'),
    path('token/', AccessTokenView.as_view(), name='access-token'),
]