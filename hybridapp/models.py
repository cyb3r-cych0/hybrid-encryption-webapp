import dateutil.utils
from django.db import models
from django.utils import timezone

import datetime

from django.conf import settings
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from Crypto.PublicKey import RSA



class KeyPair(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    public_key = models.TextField()
    private_key = models.TextField()

    def __str__(self):
        return self.user.username


@receiver(post_save, sender=User)
def create_key_pair(sender, instance, created, **kwargs):
    if created:
        print(f"[+] Creating KeyPair for user: {instance.username}")
        key_pair = KeyPair(user=instance)
        key = RSA.generate(2048)
        key_pair.public_key = key.publickey().export_key().decode('utf-8')
        key_pair.private_key = key.export_key().decode('utf-8')
        key_pair.save()
        print("[+] KeyPair created successfully.")



class EncryptedFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    case_id = models.CharField(max_length=20)
    file = models.FileField(upload_to='')
    encrypted_data = models.BinaryField()
    encryption_date = models.DateField(default=timezone.now)

    def __str__(self):
        return self.file.name


class Case(models.Model):
    caseID = models.CharField(max_length=20)
    caseName = models.CharField(max_length=20)
    caseData = models.TextField()
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    encryption_date = models.DateField(default=timezone.now)

    def __str__(self):
        return self.caseName


class EncryptCase(models.Model):
    case_id = models.CharField(unique=True, blank=False, max_length=20)
    case_name = models.CharField(max_length=100, blank=False)
    case_info = models.TextField(blank=True)
    case_file = models.FileField(upload_to='', blank=False)
    case_data = models.BinaryField(blank=False)
    user_id = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    encryption_date = models.DateField(default=timezone.now)

    def __str__(self):
        return self.case_name
