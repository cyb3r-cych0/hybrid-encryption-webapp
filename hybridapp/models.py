import django.db.models
from django.utils import timezone
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
        return self.user


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


class File(models.Model):
    case_id = models.CharField(max_length=20, blank=False)
    case_file = models.FileField(upload_to='')
    case_data = models.BinaryField()
    case_date = models.DateField(default=timezone.now)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.case_file.name


class Text(models.Model):
    case_id = models.CharField(max_length=20, blank=False)
    case_name = models.CharField(max_length=20)
    case_data = models.TextField()
    case_date = models.DateField(default=timezone.now)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return self.case_name


class TextFile(models.Model):
    case_id = models.CharField(blank=False, max_length=20)
    case_name = models.CharField(max_length=100, blank=False)
    case_info = models.TextField(blank=True)
    case_file = models.FileField(upload_to='', blank=False)
    case_data = models.BinaryField(blank=False)
    case_date = models.DateField(default=timezone.now)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return self.case_name


class DecryptInfo(models.Model):
    case_id = models.CharField(blank=False, max_length=255)
    file_name = models.CharField(max_length=255)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    decrypt_date = models.DateField(default=timezone.now)
    integrity_check = models.BooleanField()

    def __str__(self):
        return self.case_id
