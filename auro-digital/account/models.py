from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.conf import settings
from django.utils import timezone
from datetime import datetime, timedelta
from io import BytesIO
from PIL import Image
from django.core.files.uploadedfile import InMemoryUploadedFile
import sys

# Create your models here.
# Create your models here.


class app(models.Model):
    email = models.EmailField(verbose_name="email", max_length=60)
    password = models.TextField()


class MyAccountManager(BaseUserManager):
    def create_user(self, email, username, password=None):
        if not email:
            raise ValueError("Users must have an email address")
        if not username:
            raise ValueError("Please provide an email address")

        u = self.model(
            email=self.normalize_email(email),
            username=username,
        )

        u.set_password(password)
        u.save(using=self._db)
        return u

    def create_superuser(self, email, username, password):
        u = self.create_user(
            email=self.normalize_email(email),
            password=password,
            username=username
        )
        u.is_admin = True
        u.is_staff = True
        u.is_superuser = True
        u.save(using=self._db)
        return u


# Create your models here.
class Account(AbstractBaseUser):
    email = models.EmailField(verbose_name="email", max_length=60, unique=True, error_messages={'unique':'This email has already been taken sorry'})
    username = models.CharField(max_length=30, unique=True, error_messages={'unique': 'This username has already been taken sorry'})
    # unique field status
    is_teacher = models.BooleanField(default=False)

    date_joined = models.DateTimeField(verbose_name='date joined', auto_now_add=True)
    last_login = models.DateTimeField(verbose_name='last login', auto_now=True)
    is_admin = models.BooleanField(default=False)
    is_verified = models.CharField(default='false', max_length=15)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = MyAccountManager()

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True


class ResetToken(models.Model):
    code = models.CharField(max_length=5, null=False)
    email = models.CharField(max_length=200, null=False)
    expires_at = models.DateTimeField(default=timezone.now() + timezone.timedelta(hours=1))

    def __str__(self):
        return self.email

    def is_expired(self):
        return self.expires_at < timezone.now()