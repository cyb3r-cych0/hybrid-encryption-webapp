from django.contrib import admin
from .models import Text, KeyPair, File, TextFile, CipherInfo


@admin.register(KeyPair)
class KeyPairAdmin(admin.ModelAdmin):
    list_display = ['user', 'public_key', 'private_key']
    search_fields = ['user', 'public_key', 'private_key']
    list_per_page = 1


@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = ['file_id', 'file_name', 'user', 'file_date', 'file_cipher']
    search_fields = ['file_id', 'file_name', 'user', 'file_date', 'file_cipher']
    list_per_page = 1


@admin.register(Text)
class TextAdmin(admin.ModelAdmin):
    list_display = ['user', 'text_id', 'text_name', 'text_date', 'text_cipher']
    search_fields = ['user', 'text_id', 'text_name', 'text_date', 'text_cipher']
    list_per_page = 1


@admin.register(TextFile)
class TextFileAdmin(admin.ModelAdmin):
    list_display = ['textfile_id', 'textfile_name', 'textfile_file', 'user', 'textfile_text', 'textfile_date', 'textfile_cipher']
    search_fields = ['textfile_id', 'textfile_name', 'textfile_file', 'user', 'textfile_text', 'textfile_date', 'textfile_cipher']
    list_per_page = 1


@admin.register(CipherInfo)
class CipherInfoAdmin(admin.ModelAdmin):
    list_display = ['cipher_id', 'cipher_name', 'user', 'decrypt_date', 'integrity_check']
    search_fields = ['cipher_id', 'cipher_name', 'user', 'decrypt_date', 'integrity_check']
    list_per_page = 5
