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
    path('backend/user_details_backend/<id>/', views.UserDetailsBackend.as_view(), name='user_details_backend'),
    path('backend/user_cases_backend/<id>/', views.UserCasesBackend.as_view(), name='user_cases_backend'),
    path('backend/search_users/', views.SearchUsers.as_view(), name='search_users'),
    path('backend/search_cases/', views.SearchCasesBackend.as_view(), name='search_cases'),

    path('backend/view_file_backend/<id>/', views.ViewTextBackend.as_view(), name='view_file_backend'),
    path('backend/view_data_backend/<id>/', views.ViewFileBackend.as_view(), name='view_data_backend'),
    path('backend/view_report_backend/<id>/', views.ViewTextFileBackend.as_view(), name='view_report_backend'),
    path('backend/view_all_backend/',  views.ViewCasesBackend.as_view(), name='view_all_backend'),
    path('backend/filter_cases/', views.FilterCasesBackend.as_view(), name='filter_cases'),

    path('backend/filter_user_cases/<id>/', views.FilterUserCases.as_view(), name='filter_user_cases'),

    # Encrypt
    path('encrypt/upload_file', views.EncryptFile.as_view(), name='upload_file'),
    path('encrypt/encrypt_case_data/', views.EncryptText.as_view(), name='encrypt_case_data'),
    path('encrypt/encrypt_case/', views.EncryptTextFile.as_view(), name='encrypt_case'),

    path('encrypt/view_files/', views.ViewCasesEncrypt.as_view(), name='view_files'),
    path('encrypt/view_report_encrypt/<id>/', views.ViewTextFileEncrypt.as_view(), name='view_report_encrypt'),

    path('encrypt/search_cases_encrypt/', views.SearchCasesEncrypt.as_view(), name='search_cases_encrypt'),
    path('encrypt/filter_cases_encrypt/', views.FilterCasesEncrypt.as_view(), name='filter_cases_encrypt'),

    path('encrypt/view_file/<id>/', views.ViewTextEncrypt.as_view(), name='view_file'),
    path('encrypt/view_data/<id>/', views.ViewFileEncrypt.as_view(), name='view_data'),

    # Decrypt
    path('decrypt_case/<int:id>/', views.DecryptTextFile.as_view(), name='decrypt_case'),
    path('decrypt/<int:id>/', views.DecryptFile.as_view(), name='decrypt_and_download'),
    path('decrypt/view_dec_file/<id>/', views.DecryptText.as_view(), name='view_dec_file'),

    path('decrypt/search_cases_decrypt/', views.SearchCasesDecrypt.as_view(), name='search_cases_decrypt'),
    path('decrypt/search_text_cases/', views.SearchTextDecrypt.as_view(), name='search_text_cases'),
    path('decrypt/search_file_cases/', views.SearchFileDecrypt.as_view(), name='search_file_cases'),
    path('decrypt/search_report_cases/', views.SearchTextFileDecrypt.as_view(), name='search_report_cases'),

    path('decrypt/view_file_decrypt/<id>/', views.ViewTextDecrypt.as_view(), name='view_file_decrypt'),
    path('decrypt/view_report_decrypt/<id>/', views.ViewTextFileDecrypt.as_view(), name='view_report_decrypt'),
    path('decrypt/view_data_decrypt/<id>/', views.ViewFileDecrypt.as_view(), name='view_data_decrypt'),
    path('decrypt/view_all/', views.ViewCasesDecrypt.as_view(), name='view_all'),

    path('decrypt/filter_cases_decrypt/', views.FilterCasesDecrypt.as_view(), name='filter_cases_decrypt'),
    path('decrypt/filter_reports/', views.FilterTextFilesDecrypt.as_view(), name='filter_reports'),
    path('decrypt/filter_texts/', views.FilterTextsDecrypt.as_view(), name='filter_texts'),
    path('decrypt/filter_files/', views.FilterFilesDecrypt.as_view(), name='filter_files'),

    path('delete_case_text/<id>/', views.DeleteText.as_view(), name='delete_case_text'),
    path('delete_case_file/<id>/', views.DeleteFile.as_view(), name='delete_case_file'),
    path('delete_case_report/<id>/', views.DeleteTextFile.as_view(), name='delete_case_report'),

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
