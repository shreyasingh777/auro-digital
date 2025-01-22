from django.contrib.auth import authenticate
from .models import Account, ResetToken
from rest_framework.views import APIView
from .serializers import AccountSerializer, App_login
import re
from django.contrib.auth.hashers import make_password
from rest_framework import status
from rest_framework import generics
from rest_framework.response import Response
from .serializers import ChangePasswordSerializer
from rest_framework.permissions import IsAuthenticated


class signup(APIView):
    def post(self, request, *args, **kwargs):
        slizer = AccountSerializer(data=request.data)
        if slizer.is_valid():
            slizer.validated_data["password"] = make_password(slizer.validated_data.get("password"))

            print(request.data.get("rank"))

            if request.data.get("rank") == "teacher":
                rank = "teacher"
            else:
                rank = "student"

            acc = slizer.save(
                username=re.sub("[$&+,;:=?@#|'<>.^*()%!\s+\"]", "-", slizer.validated_data["username"])
            )

            if rank == "teacher":
                acc.is_teacher = True

            return Response({'status': "complete", "rank": rank, "name": request.data.get("username")})
        return Response(slizer.errors)


class loginView(APIView):
    def post(self, request, *args, **kwargs):
        slizer = App_login(data=request.data)
        if slizer.is_valid():
            e = slizer.validated_data.get("email")
            pwd = slizer.validated_data.get("password")

            if Account.objects.filter(email=e.lower().strip()).count() == 0:
                return Response({'user_error': 'No such email account'})
            else:
                if not authenticate(email=e.lower(), password=pwd):
                    return Response({'password_error': 'Password is incorrect'})
                else:
                    account = Account.objects.get(email=e.lower())

                    if not account.is_teacher:
                        rank = "student"
                    else:
                        rank = "teacher"

                    return Response({'status': 'complete', "rank": rank, "username": account.username})

        return Response(slizer.errors)


class logoutView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            request.user.auth_token.delete()
        except (AttributeError, 'ObjectDoesNotExist'):
            pass
        return Response({'status': 'logged out'})


class changePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = Account
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()

        slizer = self.get_serializer(data=request.data)

        if slizer.is_valid():
            # Check old password
            if not self.object.check_password(slizer.data.get("old_password")):
                return Response({"status": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(slizer.data.get("new_password"))
            self.object.save()

            return Response({'status': 'success'})

        return Response(slizer.errors, status=status.HTTP_400_BAD_REQUEST)


class accountUserDetails(APIView):
    def get(self, request):
        account = Account.objects.get(username=request.user)

        return Response({'email': account.email, 'username': account.username})


class updateUserDetails(APIView):
    def put(self, request, *args, **kwargs):
        password = request.data.get('password')

        account = Account.objects.get(id=request.user.id)

        if not authenticate(email=account.email, password=password):
            return Response({'status': 'Password is incorrect'})
        else:
            email = request.data.get('email').lower().strip()

            username = re.sub("[$&+,;:=?@#|'<>.^*()%!\s+\"]", "-", request.data.get('username').lower().strip())

            error_responses = []

            if Account.objects.filter(email=email).count() != 0 and Account.objects.get(email=email).email != account.email:
                error_responses.append({'email': 'Email account in use'})

            if Account.objects.filter(username=username).count() != 0 and Account.objects.get(username=username).username != account.username:
                error_responses.append({'username': 'Username in use'})

            if len(error_responses) != 0:
                return Response({'errors': error_responses})
            else:
                account.email = email
                account.username = username
                account.save()
                return Response({'status': 'Complete'})


class deleteAccount(APIView):
    def delete(self, request):
        password = request.data.get('password')

        account = Account.objects.get(id=request.user.id)

        if not authenticate(email=account.email, password=password):
            return Response({'status': 'password error'})
        else:
            account.delete()

            return Response({'status': 'deleted'})


from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
import random


def getRandomCode():
    c = ""

    for i in range(0, 4):
        c += str(random.randint(0, 9))

    return c


class sendResetPasswordToken(APIView):
    def post(self, request, *args, **kwargs):
        e = request.data.get("email").strip()

        if Account.objects.filter(email=e).count() == 0:
            return Response({'status': 'no such email in our system'})
        else:
            token_to_delete = ResetToken.objects.filter(email=e)

            if token_to_delete.count != 0:
                token_to_delete.delete()

            token = getRandomCode()

            rToken = ResetToken()

            rToken.email = e

            rToken.code = token

            rToken.save()

            html_content = render_to_string('registration/email_template.html', {'name': 'Lost User', "code": token})

            # Set up the plain text message
            text_content = strip_tags(html_content)

            # Create the email message
            subject = 'Reset your password!'

            f_email = 'kofidarkobekoe@gmail.com'

            to_email = e

            e_msg = EmailMultiAlternatives(subject, text_content, f_email, [to_email])

            # email_message = EmailMultiAlternatives(subject, text_content, to=[to_email])

            # Add the HTML content to the email message
            e_msg.attach_alternative(html_content, 'text/html')

            # Send the email
            e_msg.send()

            return Response({'status': 'sent'})


class removeExpiredTokens(APIView):
    def delete(self, request, *args, **kwargs):
        # Query for all expired tokens
        e_tokens = ResetToken.objects.filter(expires_at__lt=timezone.now())

        c = e_tokens.count()

        # Delete expired tokens
        e_tokens.delete()

        return Response({'status': 'deleted', "count": c})


class resetPasswordWithToken(APIView):
    def put(self, request, *args, **kwargs):
        # Calculate the cutoff time (1 hour ago)
        rToken = ResetToken.objects.filter(code=request.data.get("code")).filter(email=request.data.get("email"))

        if rToken.count() != 0:
            acc = Account.objects.get(email=rToken[0].email)

            acc.set_password(request.data.get("password"))

            acc.save()

            rToken.delete()

            return Response({'status': 'password updated'})
        else:
            return Response({'status': 'token expired'})