from django.contrib import admin
from django.urls import path, include
from hybridapp import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [

    # Backend
    path('backend/encrypt/', views.EncryptDashboard.as_view(), name='encrypt'),
    path('backend/decrypt/', views.DecryptDashboard.as_view(), name='decrypt'),

    path('backend/view_users_backend/', views.ViewUsersBackend.as_view(), name='view_users_backend'),
    path('backend/view_user_details_backend/<id>/', views.ViewUserDetailsBackend.as_view(), name='view_user_details_backend'),
    path('backend/view_user_records_backend/<id>/', views.ViewUserRecordsBackend.as_view(), name='view_user_records_backend'),
    path('backend/search_users_backend/', views.SearchUsersBackend.as_view(), name='search_users_backend'),
    path('backend/search_cipher_records_backend/', views.SearchCipherRecordsBackend.as_view(), name='search_cipher_records_backend'),

    path('backend/view_cipher_text_backend/<id>/', views.ViewCipherTextBackend.as_view(), name='view_cipher_text_backend'),
    path('backend/view_cipher_file_backend/<id>/', views.ViewCipherFileBackend.as_view(), name='view_cipher_file_backend'),
    path('backend/view_cipher_textfile_backend/<id>/', views.ViewCipherTextFileBackend.as_view(), name='view_cipher_textfile_backend'),
    path('backend/view_cipher_records_backend/',  views.ViewCipherRecordsBackend.as_view(), name='view_cipher_records_backend'),
    path('backend/filter_cipher_records_backend/', views.FilterCipherRecordsBackend.as_view(), name='filter_cipher_records_backend'),

    path('backend/filter_user_records_backend/<id>/', views.FilterUserRecordsBackend.as_view(), name='filter_user_records_backend'),

    # Encrypt
    path('encrypt/encrypt_file', views.EncryptFile.as_view(), name='encrypt_file'),
    path('encrypt/encrypt_text/', views.EncryptText.as_view(), name='encrypt_text'),
    path('encrypt/encrypt_textfile/', views.EncryptTextFile.as_view(), name='encrypt_textfile'),

    path('encrypt/view_cipher_records/', views.ViewCipherRecords.as_view(), name='view_cipher_records'),
    path('encrypt/search_cipher_records/', views.SearchCipherRecords.as_view(), name='search_cipher_records'),
    path('encrypt/filter_cipher_records/', views.FilterCipherRecords.as_view(), name='filter_cipher_records'),

    path('encrypt/view_cipher_file/<id>/', views.ViewCipherFileEncrypt.as_view(), name='view_cipher_file'),
    path('encrypt/view_cipher_text/<id>/', views.ViewCipherText.as_view(), name='view_cipher_text'),
    path('encrypt/view_cipher_textfile/<id>/', views.ViewCipherTextFileEncrypt.as_view(), name='view_cipher_textfile'),

    # Decrypt
    path('decrypt/decrypt_textfile/<int:id>/', views.DecryptTextFile.as_view(), name='decrypt_textfile'),
    path('decrypt/decrypt_file/<int:id>/', views.DecryptFile.as_view(), name='decrypt_file'),
    path('decrypt/decrypt_text/<id>/', views.DecryptText.as_view(), name='decrypt_text'),

    path('decrypt/decrypt_details', views.ViewDecryptDetails.as_view(), name='decrypt_details'),
    path('decrypt/view_decrypt_details/<id>/', views.ViewDecryptedDetails.as_view(), name='view_decrypt_details'),

    path('decrypt/search_records_decrypt/', views.SearchRecordsDecrypt.as_view(), name='search_records_decrypt'),
    path('decrypt/search_cipher_text/', views.SearchTextDecrypt.as_view(), name='search_cipher_text'),
    path('decrypt/search_cipher_file/', views.SearchFileDecrypt.as_view(), name='search_cipher_file'),
    path('decrypt/search_cipher_textfile/', views.SearchTextFileDecrypt.as_view(), name='search_cipher_textfile'),

    path('decrypt/view_cipher_text/<id>/', views.ViewCipherTextDecrypt.as_view(), name='view_cipher_text'),
    path('decrypt/view_cipher_textfile/<id>/', views.ViewCipherTextFileDecrypt.as_view(), name='view_cipher_textfile'),
    path('decrypt/view_cipher_file/<id>/', views.ViewCipherFileDecrypt.as_view(), name='view_cipher_file'),
    path('decrypt/view_cipher_records_all/', views.ViewCipherRecordsDecrypt.as_view(), name='view_cipher_records_all'),

    path('decrypt/filter_records_decrypt/', views.FilterRecordsDecrypt.as_view(), name='filter_records_decrypt'),
    path('decrypt/filter_cipher_textfile/', views.FilterTextFilesDecrypt.as_view(), name='filter_cipher_textfile'),
    path('decrypt/filter_cipher_text/', views.FilterTextsDecrypt.as_view(), name='filter_cipher_text'),
    path('decrypt/filter_cipher_file/', views.FilterFilesDecrypt.as_view(), name='filter_cipher_file'),

    path('delete_case_text/<id>/', views.DeleteText.as_view(), name='delete_case_text'),
    path('delete_case_file/<id>/', views.DeleteFile.as_view(), name='delete_case_file'),
    path('delete_case_report/<id>/', views.DeleteTextFile.as_view(), name='delete_case_report'),
    path('delete_decrypt_info/<int:id>/', views.DeleteDecryptInfo.as_view(), name='delete_decrypt_info'),

    # Admin
    path('login/', include('django.contrib.auth.urls')),
    path('admin/', admin.site.urls),

    path('', views.FrontEnd.as_view(), name='frontend'),
    path('backend/', views.BackEnd.as_view(), name='backend'),
    path('registration/register_user/', views.RegisterUser.as_view(), name='register_user'),

    # Downloads
    path('export_cases_csv/', views.ExportTextsCSV.as_view(), name='export_cases_csv'),
    path('export_files_csv/', views.ExportFilesCSV.as_view(), name='export_files_csv'),
    path('export_report_csv/', views.ExportTextFilesCSV.as_view(), name='export_report_csv'),

    # Redundant Code
    path('update/<id>/', views.update, name='update'),
]

# media
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
