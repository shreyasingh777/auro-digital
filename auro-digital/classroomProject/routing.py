from django.urls import re_path, path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/socket-server/', consumers.ChatConsumer.as_asgi()),
    path('ws/classroom/<slug:slug>/<slug:username>', consumers.ClassConsumer.as_asgi())
]