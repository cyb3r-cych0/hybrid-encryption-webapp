from django.contrib import admin
from .models import Case, KeyPair, EncryptedFile, EncryptCase


# Register your models here.
# admin.site.register(Car)

@admin.register(Case)
class CaseAdmin(admin.ModelAdmin):
    list_display = ['user', 'caseID', 'caseName', 'encryption_date', 'caseData']
    search_fields = ['user', 'caseID', 'caseName', 'encryption_date', 'caseData']
    list_per_page = 1

@admin.register(KeyPair)
class KeyPairAdmin(admin.ModelAdmin):
    list_display = ['user', 'public_key', 'private_key']
    search_fields = ['user', 'public_key', 'private_key']
    list_per_page = 1

@admin.register(EncryptedFile)
class EncryptedFileAdmin(admin.ModelAdmin):
    list_display = ['case_id', 'file', 'user', 'encryption_date', 'encrypted_data']
    search_fields = ['case_id', 'file', 'user', 'encryption_date', 'encrypted_data']
    list_per_page = 1

@admin.register(EncryptCase)
class EncryptCaseAdmin(admin.ModelAdmin):
    list_display = ['case_id', 'case_name', 'case_file', 'user_id', 'encryption_date', 'case_info', 'case_data']
    search_fields = ['case_id', 'case_name', 'case_file', 'user_id', 'encryption_date', 'case_info', 'case_data']
    list_per_page = 1
