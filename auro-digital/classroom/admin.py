from django.contrib import admin
from .models import Participant, ChatParticipant

# Register your models here.
admin.site.register(Participant)
admin.site.register(ChatParticipant)