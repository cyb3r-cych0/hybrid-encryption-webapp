from django.contrib import admin
from .models import Text, KeyPair, File, TextFile


@admin.register(Text)
class TextAdmin(admin.ModelAdmin):
    list_display = ['user', 'case_id', 'case_name', 'case_date', 'case_data']
    search_fields = ['user', 'case_id', 'case_name', 'case_date', 'case_data']
    list_per_page = 1


@admin.register(KeyPair)
class KeyPairAdmin(admin.ModelAdmin):
    list_display = ['user', 'public_key', 'private_key']
    search_fields = ['user', 'public_key', 'private_key']
    list_per_page = 1


@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = ['case_id', 'case_file', 'user', 'case_date', 'case_data']
    search_fields = ['case_id', 'case_file', 'user', 'case_date', 'case_data']
    list_per_page = 1


@admin.register(TextFile)
class TextFileAdmin(admin.ModelAdmin):
    list_display = ['case_id', 'case_name', 'case_file', 'user', 'case_date', 'case_info', 'case_data']
    search_fields = ['case_id', 'case_name', 'case_file', 'user', 'case_date', 'case_info', 'case_data']
    list_per_page = 1
