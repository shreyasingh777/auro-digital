from django.http import JsonResponse
from .models import ChatParticipant
from account.models import Account
from rest_framework.authtoken.models import Token


# Create your views here.
def getChatParticipant(request):
    r = request.GET.get("room")

    count_Chat = ChatParticipant.objects.filter(room=r).count()

    if count_Chat == 0:
        participant = ChatParticipant()
        participant.user = Account.objects.all()[0]
        participant.room = r
        participant.save()
    else:
        if count_Chat == Token.objects.all().count():
            all_participants = ChatParticipant.objects.filter(room=r)

            all_participants.delete()

            participant = ChatParticipant()

            participant.user = Account.objects.all()[0]

            participant.room = r

            participant.save()
        else:
            participant = ChatParticipant()
            participant.user = Account.objects.all()[count_Chat]
            participant.room = r
            participant.save()

    return JsonResponse({
        "username": str(participant.user.username)
    }, safe=False)