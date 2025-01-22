import json
from channels.generic.websocket import WebsocketConsumer
from asgiref.sync import async_to_sync
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from classroom.models import Participant
from rest_framework.authtoken.models import Token


class ChatConsumer(WebsocketConsumer):
    def connect(self):
        self.room_group_name = "test"

        async_to_sync(self.channel_layer.group_add)(
            self.room_group_name,
            self.channel_name
        )

        self.accept()

        self.send(text_data=json.dumps({
            "type": "connection_established",
            "message": "connected"
        }))

    def disconnect(self, close_code):
        pass

    def receive(self, text_data):
        text_data_json = json.loads(text_data)

        message = text_data_json["message"]

        username = text_data_json["username"]

        async_to_sync(self.channel_layer.group_send)(
            self.room_group_name,
            {
                "type": "chat_message",
                "message": message,
                "username": username
            }
        )

    def chat_message(self, event):
        message = event["message"]

        username = event["username"]

        self.send(text_data=json.dumps({
            "type": "chat",
            "message": message,
            "username": username
        }))


class ClassConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_group_name = self.scope["url_route"]["kwargs"]["slug"]

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        user_disconnected = self.scope["url_route"]["kwargs"]["username"]

        await self.channel_layer.group_send(
            self.room_group_name,
            {
                "type": "user_disconnected",
                "user_disconnected": user_disconnected,
            }
        )

    async def user_disconnected(self, event):
        user_disconnected = event["user_disconnected"]

        room = self.scope["url_route"]["kwargs"]["slug"]

        await self.delete_participants(room)

        await self.send(text_data=json.dumps({
            "type": "user_disconnected",
            "user_disconnected": user_disconnected,
        }))

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)

        room = self.scope["url_route"]["kwargs"]["slug"]

        if "get_token" in text_data_json:
            [token, username, reload] = await self.getTokenForUser(room)

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "new_token",
                    "token": token,
                    "username": username,
                    "reload": reload
                }
            )
        elif "new_user" in text_data_json:
            user = await self.getTokenUser(text_data_json["token"])

            if user.is_teacher:
                rank = "teacher"
            else:
                rank = "student"

            shouldAddParticipant = await self.add_participants(room, user)

            if shouldAddParticipant:
                all_participants = await self.get_participants(room)

                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        "type": "new_user",
                        "user_list": all_participants,
                        "rank": rank,
                        "reload": text_data_json["reload"]
                    }
                )
        else:
            if "negotiation" in text_data_json:
                name = text_data_json["name"]

                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        "type": "new_negotiation",
                        "user_name": name,
                    }
                )

            if "offer_negotiation" in text_data_json:
                user_to_answer = text_data_json["to_user"]

                offer_sdp = text_data_json["offer_sdp"]

                user_offering = text_data_json["name"]

                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        "type": "answer_offer_sdp",
                        "user_to_answer": user_to_answer,
                        "offer_sdp": offer_sdp,
                        "user_offering": user_offering
                    }
                )

            if "answer_negotiation_sdp_complete" in text_data_json:
                candidate = text_data_json["candidate"]

                answer_sdp = text_data_json["answer_sdp"]

                to_user = text_data_json["to_user"]

                who_answered = text_data_json["who_answered"]

                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        "type": "offer_set_sdp",
                        "candidate": candidate,
                        "answer_sdp": answer_sdp,
                        "to_user": to_user,
                        "who_answered": who_answered
                    }
                )

            if "screen_offer_negotiation" in text_data_json:
                user_to_answer = text_data_json["to_user"]

                offer_sdp = text_data_json["screen_offer_sdp"]

                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        "type": "screen_offer_negotiation",
                        "to_user": user_to_answer,
                        "offer_sdp": offer_sdp
                    }
                )

            if "answer_negotiation_sdp_screenshot_complete" in text_data_json:
                who_answered = text_data_json["who_answered"]

                candidate = text_data_json["candidate"]

                answer_sdp = text_data_json["answer_sdp"]

                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        "type": "screen_offer_set_sdp",
                        "to_user": who_answered,
                        "answer_sdp": answer_sdp,
                        "candidate": candidate
                    }
                )

    async def screen_offer_set_sdp(self, event):
        candidate = event["candidate"]

        answer_sdp = event["answer_sdp"]

        to_user = event["to_user"]

        await self.send(text_data=json.dumps({
            "type": "screen_offer_set_sdp",
            "candidate": candidate,
            "answer_sdp": answer_sdp,
            "to_user": to_user,
        }))

    async def screen_offer_negotiation(self, event):
        to_user = event["to_user"]

        offer_sdp = event["offer_sdp"]

        await self.send(text_data=json.dumps({
            "type": "screen_offer_negotiation",
            "to_user": to_user,
            "offer_sdp": offer_sdp
        }))

    async def offer_set_sdp(self, event):
        candidate = event["candidate"]

        answer_sdp = event["answer_sdp"]

        to_user = event["to_user"]

        who_answered = event["who_answered"]

        await self.send(text_data=json.dumps({
            "type": "offer_set_sdp",
            "candidate": candidate,
            "answer_sdp": answer_sdp,
            "to_user": to_user,
            "who_answered": who_answered
        }))

    async def answer_offer_sdp(self, event):
        user_to_answer = event["user_to_answer"]

        offer_sdp = event["offer_sdp"]

        user_offering = event["user_offering"]

        await self.send(text_data=json.dumps({
            "type": "answer_offer_sdp",
            "user_to_answer": user_to_answer,
            "offer_sdp": offer_sdp,
            "user_offering": user_offering
        }))

    async def new_negotiation(self, event):
        user_name = event["user_name"]

        await self.send(text_data=json.dumps({
            "type": "negotiation",
            "user_name": user_name,
        }))

    async def new_user(self, event):
        user_list = event["user_list"]

        rank = event["rank"]

        reload = event["reload"]

        await self.send(text_data=json.dumps({
            "type": "new_user",
            "user_list": user_list,
            "rank": rank,
            "reload": reload
        }))

    async def new_token(self, event):
        user_token = event["token"]

        user_name = event["username"]

        reload = event["reload"]

        await self.send(text_data=json.dumps({
            "type": "new_token",
            "token": user_token,
            "username": user_name,
            "reload": reload
        }))

    @database_sync_to_async
    def add_participants(self, room, user):
        if Participant.objects.filter(user=user).filter(room=room).count() == 0:
            participant = Participant()
            participant.user = user
            participant.room = room
            participant.save()
            return True
        else:
            return False

    @database_sync_to_async
    def get_participants(self, room):
        all_participants = Participant.objects.filter(room=room)

        all_participants_to_send = []

        for participant in all_participants:
            if participant.user.is_teacher:
                rank = "teacher"
            else:
                rank = "student"

            all_participants_to_send.append(
                {
                    'user': str(participant.user), "rank": rank,
                    "id": str(participant.id)
                }
            )

        return all_participants_to_send

    @database_sync_to_async
    def getTokenUser(self, token):
        user = Token.objects.get(key=token).user

        return user

    @database_sync_to_async
    def getTokenForUser(self, room):
        participant_number = Participant.objects.filter(room=room).count()

        try:
            token = Token.objects.all()[participant_number]

            reload = False
        except IndexError:
            Participant.objects.filter(room=room).delete()

            token = Token.objects.all()[0]

            reload = True

        return token.key, str(token.user), reload

    @database_sync_to_async
    def delete_participants(self, room):
        Participant.objects.filter(room=room).delete()