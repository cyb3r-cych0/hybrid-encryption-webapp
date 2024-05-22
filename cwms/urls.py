from django.contrib import admin
from django.urls import path, include
from hybridapp import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [

    path('encrypt/upload_file', views.upload_and_encrypt_file, name='upload_file'),
    # path('encrypt/file_list/', views.file_list, name='file_list'),
    path('decrypt/<int:id>/', views.decrypt_and_download_file, name='decrypt_and_download'),
    path('decrypt_case_data/<int:id>/', views.decrypt_case_data, name='decrypt_case_data'),
    path('decrypt_case/<int:id>/', views.decrypt_case, name='decrypt_case'),

    path('encrypt/generate_keys/', views.generate_keys, name='generate_keys'),
    path('encrypt/encrypt_case_data/', views.encrypt_case_data, name='encrypt_case_data'),
    path('encrypt/encrypt_case/', views.encrypt_case, name='encrypt_case'),
    path('encrypt/view_dec_file/<id>/', views.decrypt_case_data, name='view_dec_file'),

    path('backend/encrypt/', views.encrypt, name='encrypt'),
    path('backend/decrypt/', views.decrypt, name='decrypt'),

# <<<<<<< HEAD
# =======
    path('backend/view_users_backend/', views.view_users_backend, name='view_users_backend'),
    path('backend/user_details_backend/<id>/', views.user_details_backend, name='user_details_backend'),
    path('backend/user_cases_backend/<id>/', views.user_cases_backend, name='user_cases_backend'),
    path('backend/filter_user_cases/<id>/', views.filter_user_cases, name='filter_user_cases'),
    path('backend/search_users/', views.search_users, name='search_users'),

# >>>>>>> ac2bd1e (cms-v0.3)
    path('decrypt/search_text_cases/', views.search_text_cases, name='search_text_cases'),
    path('decrypt/search_file_cases/', views.search_file_cases, name='search_file_cases'),
    path('decrypt/search_report_cases/', views.search_report_cases, name='search_report_cases'),
    path('backend/search_cases/', views.search_cases, name='search_cases'),
    path('encrypt/search_cases_encrypt/', views.search_cases_encrypt, name='search_cases_encrypt'),
    path('decrypt/search_cases_decrypt/', views.search_cases_decrypt, name='search_cases_decrypt'),
    # path('backend/search_form/', views.search_form, name='search_form'),

    path('decrypt/decrypt_success', views.decrypt_success, name='decrypt_success'),

    # Admin
    path('admin/', admin.site.urls),

    # Frontend
    path('', views.frontend, name='frontend'),

    # Backend
    path('backend/', views.backend, name='backend'),

    path('registration/register_user/', views.register_user, name='register_user'),

    path('encrypt/view_files/', views.view_files, name='view_files'),

    path('encrypt/view_file/<id>/',  views.view_file, name='view_file'),
    path('backend/view_file_backend/<id>/',  views.view_file_backend, name='view_file_backend'),
    path('decrypt/view_file_decrypt/<id>/',  views.view_file_decrypt, name='view_file_decrypt'),
    path('decrypt/view_data_decrypt/<id>/',  views.view_data_decrypt, name='view_data_decrypt'),
    path('decrypt/view_report_decrypt/<id>/',  views.view_report_decrypt, name='view_report_decrypt'),
    path('encrypt/view_report_encrypt/<id>/',  views.view_report_encrypt, name='view_report_encrypt'),
    path('backend/view_report_backend/<id>/',  views.view_report_backend, name='view_report_backend'),
    path('encrypt/view_data/<id>/',  views.view_data, name='view_data'),
    path('backend/view_data_backend/<id>/',  views.view_data_backend, name='view_data_backend'),
    path('decrypt/view_all/',  views.view_all, name='view_all'),
    path('backend/view_all_backend/',  views.view_all_backend, name='view_all_backend'),


    # Login/Logout
    path('login/', include('django.contrib.auth.urls')),

    path('filter_reports/', views.filter_reports, name='filter_reports'),
    path('filter_texts/', views.filter_texts, name='filter_texts'),
    path('filter_files/', views.filter_files, name='filter_files'),
    path('backend/filter_cases/', views.filter_cases, name='filter_cases'),
    path('encrypt/filter_cases_encrypt/', views.filter_cases_encrypt, name='filter_cases_encrypt'),
    path('decrypt/filter_cases_decrypt/', views.filter_cases_decrypt, name='filter_cases_decrypt'),

    path('update/<id>/', views.update, name='update'),
    path('delete_case_text/<id>/', views.delete_case_text, name='delete_case_text'),
    path('delete_case_file/<id>/', views.delete_case_file, name='delete_case_file'),
    path('delete_case_report/<id>/', views.delete_case_report, name='delete_case_report'),
    path('export_cases_csv/', views.export_cases_csv, name='export_cases_csv'),
    path('export_files_csv/', views.export_files_csv, name='export_files_csv'),
    path('export_report_csv/', views.export_report_csv, name='export_report_csv'),

    path('print_enc_data/', views.print_enc_data, name='print_enc_data'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
