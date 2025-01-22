from django.db import models
from django.conf import settings


# Create your models here.
class Participant(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    room = models.CharField(max_length=10, null=True)
    time_joined = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.user)


class ChatParticipant(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    room = models.CharField(max_length=10, null=True)
    time_joined = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.user)