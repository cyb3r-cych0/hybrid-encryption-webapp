import base64
import csv
import io
import time
import zipfile

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpResponse, Http404
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.views.decorators.cache import cache_control
from django.utils.decorators import method_decorator
from django.views.generic import View
from django.utils import timezone

from .forms import TextForm, RegisterForm, TextFileForm, FileForm
from .models import KeyPair, File, Text, TextFile, CipherInfo



""" START FRONTEND / BACKEND"""

import psutil
from django.http import JsonResponse
from django.db import connection


def system_status_api(request):
    # 1. Get Metrics
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent

    # 2. Check DB
    try:
        connection.ensure_connection()
        db_status = "Online"
    except:
        db_status = "Offline"

    # Return data as JSON
    return JsonResponse({
        'cpu': cpu,
        'ram': ram,
        'db': db_status
    })

class FrontEnd(View):
    @staticmethod
    def get(request):
        return render(request, 'frontend.html')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class BackEnd(View):
    @staticmethod
    def get(request):
        date = timezone.now()
        user = request.user

        try:
            users = User.objects.all().count()
            active_users = User.objects.filter(is_active=True).count()
            admin_users = User.objects.filter(is_superuser=True).count()
            standard_users = User.objects.filter(is_staff=False).count()

            texts = Text.objects.all().count()
            files = File.objects.all().count()
            textfiles = TextFile.objects.all().count()
            total_ciphers = files + texts + textfiles

            total_deciphers = CipherInfo.objects.all().count()

            cipher_keys = KeyPair.objects.all().count()

            integrity_check = CipherInfo.objects.filter(integrity_check=True).count()

            if integrity_check == 0:
                integrity_rate = 0
            else:
                integrity_rate = integrity_check / total_deciphers * 100


            context = {
                'user': user,
                'users': users,
                'active_users': active_users,
                'admin_users': admin_users,
                'standard_users': standard_users,
                'total_ciphers': total_ciphers,
                'total_deciphers': total_deciphers,
                'cipher_keys': cipher_keys,
                'integrity_rate': integrity_rate,
                'date': date,
            }
            return render(request, 'backend.html', context)
        except Exception as e:
            messages.error(request, f'FAILED! Login Failed {str(e)}')
            return redirect('login')

""" END FRONTEND / BACKEND"""


""" START USER INFO """

class RegisterUser(View):
    @staticmethod
    def get(request):
        form = RegisterForm()
        context = {
            'form': form
        }
        return render(request, 'registration/register_user.html', context)

    @staticmethod
    def post(request):
        form = RegisterForm(request.POST)
        try:
            if form.is_valid():
                form.save()
                username = form.cleaned_data.get('username')
                messages.success(request, f'SUCCESS! User {username} Registered')
                return redirect('login')
            else:
                messages.error(request, 'FAILED! Registration Unsuccessful')
                context = {
                    'form': form
                }
                return render(request, 'registration/register_user.html', context)
        except Exception as e:
            return redirect('register_user')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewUsersBackend(View):
    @staticmethod
    def get(request):
        user = request.user
        is_superuser =request.user.is_superuser

        users_table = User.objects.filter().order_by('id')[:5]
        active_users = User.objects.filter(is_active=True).count()
        staff_users = User.objects.filter(is_staff=True).count()
        standard_users = User.objects.filter(is_staff=False).count()

        context = {
            'users': users_table,
            'active_users': active_users,
            'staff_users': staff_users,
            'standard_users': standard_users,
            'user': user
        }
        return render(request, 'backend/view_users_backend.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewUserDetailsBackend(View):
    @staticmethod
    def get(request, id):
        try:
            user = request.user
            user_details = get_object_or_404(User, id=id)
            keypair = get_object_or_404(KeyPair, id=id)
            keypair_num = KeyPair.objects.all().count()
            texts = Text.objects.filter(user=user_details).count()
            files = File.objects.filter(user=user_details).count()
            textfiles = TextFile.objects.filter(user=user_details).count()
            encrypted_data = files + texts + textfiles
            decrypted_data = CipherInfo.objects.filter(user_id=user_details).count()
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('view_user_details_backend')
        context = {
            'keypair': keypair,
            'keypair_num': keypair_num,
            'user_details': user_details,
            'encrypted_data': encrypted_data,
            'decrypted_data': decrypted_data,
            'user': user,
        }
        return render(request, 'backend/view_user_details_backend.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewAllUsersBackend(View):
    @staticmethod
    def get(request, id):
        try:
            user = request.user
            user_details = get_object_or_404(User, id=id)
            keypair = KeyPair.objects.filter(user_id=user_details).count()
            decrypted_data = CipherInfo.objects.filter(user_id=user_details).count()

            text = Text.objects.filter(user=user_details).count()
            file = File.objects.filter(user=user_details).count()
            textfile = TextFile.objects.filter(user=user_details).count()
            encrypted_data = file + text + textfile
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            raise Http404(f'User Details Not Found! {str(e)}')
        context = {
            'user_details': user_details,
            'keypair': keypair,
            'decrypted_data': decrypted_data,
            'encrypted_data': encrypted_data,
            'user': user
        }
        return render(request, 'backend/view_all_users.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class SearchUsersBackend(View):
    @staticmethod
    def get(request):
        user = request.user
        query = request.GET.get('q')
        try:
            if query:
                active_users = User.objects.filter(is_active=True).count()
                staff_users = User.objects.filter(is_staff=True).count()
                standard_users = User.objects.filter(is_staff=False).count()

                q_users = User.objects.filter(username__icontains=query)
                count = q_users.count()
                context = {
                    'user': user,
                    'count': count,
                    'q_users': q_users,
                    'active_users': active_users,
                    'staff_users': staff_users,
                    'standard_users': standard_users
                }
                messages.success(request, f'{count} - Matching Users Found')
            else:
                active_users = User.objects.filter(is_active=True).count()
                staff_users = User.objects.filter(is_staff=True).count()
                standard_users = User.objects.filter(is_staff=False).count()

                context = {
                    'user': user,
                    'active_users': active_users,
                    'staff_users': staff_users,
                    'standard_users': standard_users
                }
                messages.error(request, f'Type User Name or  ID In TextBox To Search All Users')
            return render(request, 'backend/search_users_backend.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('search_users_backend')

""" END USER INFO """


""" START ENCRYPT RECORDS """

@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class EncryptTextFile(View):
    @staticmethod
    def get(request):
        form = TextFileForm()
        textfile = TextFile.objects.filter(user=request.user).order_by('-id')[:2]
        date = timezone.now()

        context = {
            'form': form,
            'textfile': textfile,
            'date': date
        }
        return render(request, 'encrypt/encrypt_textfile.html', context)

    @staticmethod
    def post(request):
        form = TextFileForm(request.POST, request.FILES)
        textfile = TextFile.objects.filter(user=request.user).order_by('-id')[:2]
        date = timezone.now()
        if form.is_valid():
            try:
                user = request.user
                textfile_id = form.cleaned_data['textfile_id']
                textfile_name = form.cleaned_data['textfile_name']
                textfile_text = form.cleaned_data['textfile_text'].encode()
                textfile_file = form.cleaned_data['textfile_file'].read()

                # Fetch user's RSA public key
                key_pair = KeyPair.objects.get(user=user)
                public_key = RSA.import_key(key_pair.public_key)

                # Hash object for file verification
                file_hash_object = SHA256.new()
                file_hash_object.update(textfile_file)
                file_original_hash = file_hash_object.digest()

                text_hash_object = SHA256.new()
                text_hash_object.update(textfile_text)
                text_original_hash = text_hash_object.digest()

                # Encrypt file data
                session_key = get_random_bytes(16)
                cipher_rsa = PKCS1_OAEP.new(public_key)
                enc_session_key = cipher_rsa.encrypt(session_key)
                cipher_aes = AES.new(session_key, AES.MODE_EAX)
                file_cipher, tag = cipher_aes.encrypt_and_digest(textfile_file)

                # Generate AES, pad & encrypted text data
                text_cipher_rsa = PKCS1_OAEP.new(public_key)
                text_session_key = get_random_bytes(16)
                text_cipher_aes = AES.new(text_session_key, AES.MODE_EAX)
                text_cipher, text_tag = text_cipher_aes.encrypt_and_digest(textfile_text)
                text_enc_session_key = text_cipher_rsa.encrypt(text_session_key)

                # Store encrypted data in database
                cipher_file = enc_session_key + cipher_aes.nonce + tag + file_cipher + file_original_hash
                cipher_text = base64.b64encode(
                    text_enc_session_key + text_cipher_aes.nonce + text_tag + text_cipher + text_original_hash).decode(
                    'utf-8')

                # Save encrypted case data to the database
                new_case = TextFile.objects.create(
                    textfile_id=textfile_id,
                    textfile_name=textfile_name,
                    textfile_text=cipher_text,
                    textfile_file=form.cleaned_data['textfile_file'],
                    textfile_cipher=cipher_file,
                    user=user
                )

                # software feedback
                if new_case:
                    messages.success(request, f'SUCCESS! TextFile Encrypted __ {textfile_name} Cipher Saved __')
                    return redirect('encrypt_textfile')
            except Exception as e:
                messages.error(request, f'FAILED! TextFile Not Encrypted __ Error: {str(e)} __')
                return redirect('encrypt_textfile')
        context = {
            'form': form,
            'textfile': textfile,
            'date': date
        }
        return render(request, 'encrypt/encrypt_textfile.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class EncryptText(View):
    @staticmethod
    def get(request):
        form = TextForm()
        text = Text.objects.filter(user=request.user).order_by('-id')[:2]
        date = timezone.now()
        context = {
            'form': form,
            'text': text,
            'date': date
        }
        return render(request, 'encrypt/encrypt_text.html', context)

    @staticmethod
    def post(request):
        form = TextForm(request.POST, request.FILES)
        text = Text.objects.filter(user=request.user).order_by('-id')[:2]
        date = timezone.now()
        if form.is_valid():
            try:
                user = request.user
                text_id = form.cleaned_data['text_id']
                text_name = form.cleaned_data['text_name'].encode()

                # Fetch user's RSA public key
                key_pair = KeyPair.objects.get(user=user)
                public_key = RSA.import_key(key_pair.public_key)

                # Hash object for verification
                hash_object = SHA256.new()
                hash_object.update(text_name)
                original_hash = hash_object.digest()

                # Generate AES, pad & encrypted data
                cipher_rsa = PKCS1_OAEP.new(public_key)
                session_key = get_random_bytes(16)
                cipher_aes = AES.new(session_key, AES.MODE_EAX)
                ciphertext, tag = cipher_aes.encrypt_and_digest(text_name)
                enc_session_key = cipher_rsa.encrypt(session_key)
                cipher = base64.b64encode(enc_session_key + cipher_aes.nonce + tag + ciphertext + original_hash).decode('utf-8')

                # Save encrypted case data to the database
                cipher_text = Text.objects.create(
                    user=user,
                    text_id=text_id,
                    text_name=text_name,
                    text_cipher=cipher,
                )

                # software feedback
                if cipher_text:
                    messages.success(
                        request, f'SUCCESS! Text Encrypted __ {cipher_text.text_name} Cipher Saved __'
                    )
                    return redirect('encrypt_text')
            except Exception as e:
                messages.error(request, f'FAILED! Text Not Encrypted __ Error: {str(e)} __')
                return redirect('encrypt_text')
        context = {
            'form': form,
            'text': text,
            'date': date
        }
        return render(request, 'encrypt/encrypt_text.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class EncryptFile(View):
    @staticmethod
    def get(request):
        form = FileForm()
        file = File.objects.filter(user=request.user).order_by('-id')[:1]
        date = timezone.now()
        context = {
            'form': form,
            'file': file,
            'date': date,
        }
        return render(request, 'encrypt/encrypt_file.html', context)

    @staticmethod
    def post(request):
        form = FileForm(request.POST, request.FILES)
        file = File.objects.filter(user=request.user).order_by('-id')[:2]
        date = timezone.now()
        if form.is_valid():
            try:
                user = request.user
                file_id = form.cleaned_data['file_id']
                file_name = form.cleaned_data['file_name'].read()

                # Fetch user's RSA public key
                key_pair = KeyPair.objects.get(user=user)
                public_key = RSA.import_key(key_pair.public_key)

                # Hash object for verification
                hash_object = SHA256.new()
                hash_object.update(file_name)
                original_hash = hash_object.digest()

                # Encrypt file data
                session_key = get_random_bytes(16)
                cipher_rsa = PKCS1_OAEP.new(public_key)
                enc_session_key = cipher_rsa.encrypt(session_key)
                cipher_aes = AES.new(session_key, AES.MODE_EAX)
                ciphertext, tag = cipher_aes.encrypt_and_digest(file_name)
                cipher = enc_session_key + cipher_aes.nonce + tag + ciphertext + original_hash

                # Store encrypted data in database
                cipher_file = File.objects.create(
                    user=user,
                    file_id=file_id,
                    file_name=form.cleaned_data['file_name'],
                    file_cipher=cipher,
                )

                # software feedback
                if cipher_file:
                    messages.success(
                        request, f'SUCCESS! File Encrypted __ {cipher_file.file_name} Cipher Saved __'
                    )
                    return redirect('encrypt_file')
            except Exception as e:
                messages.error(
                    request, f'FAILED! File Not Encrypted __ Error: {str(e)} __'
                )
                return redirect('encrypt_file')
        context = {
            'form': form,
            'file': file,
            'date': date
        }
        return render(request, 'encrypt/encrypt_file.html', context)

""" END ENCRYPT RECORDS """


""" START DECRYPT RECORDS """

class DecryptDetails:
    @staticmethod
    def save_decrypt_details(user, cipher_id, cipher_name, integrity_check):
        # Save the decrypt details to the database
        CipherInfo.objects.create(
            user=user,
            cipher_id=cipher_id,
            cipher_name=cipher_name,
            integrity_check=integrity_check
        )


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class DecryptTextFile(View):
    @staticmethod
    def get_file(id):
        # get encrypted data RSA private key for decryption
        encrypted_file = get_object_or_404(TextFile, id=id)
        private_key = RSA.import_key(KeyPair.objects.get(user=encrypted_file.user).private_key)

        # Extract components from the decrypted data with correct lengths for slicing
        encrypted_file_data = encrypted_file.textfile_cipher
        key_len = private_key.size_in_bytes()
        enc_session_key = encrypted_file_data[:key_len]
        nonce = encrypted_file_data[key_len:key_len + 16]
        tag = encrypted_file_data[key_len + 16:key_len + 32]
        ciphertext = encrypted_file_data[key_len + 32:-32]
        file_original_hash = encrypted_file_data[-32:]

        # Decrypt file data
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
        decrypted_file_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return decrypted_file_data, file_original_hash

    @staticmethod
    def get_text(id):
        # get encrypted data RSA private key for decryption
        encrypted_file = get_object_or_404(TextFile, id=id)

        # Fetch user's private key
        key_pair = KeyPair.objects.get(user=encrypted_file.user)
        private_ky = RSA.import_key(key_pair.private_key)

        text_cipher_rsa = PKCS1_OAEP.new(private_ky)
        encrypted_text_data = base64.b64decode(encrypted_file.textfile_text)  # ensure this is decoding correctly

        # Extract components from the decrypted data with correct lengths for slicing
        ky_len = private_ky.size_in_bytes()
        text_enc_session_key = encrypted_text_data[:ky_len]
        text_nonce = encrypted_text_data[ky_len:ky_len + 16]
        text_tag = encrypted_text_data[ky_len + 16:ky_len + 32]
        text_ciphertext = encrypted_text_data[ky_len + 32:-32]
        text_original_hash = encrypted_text_data[-32:]

        # Decrypt the AES session key with RSA private key
        text_session_key = text_cipher_rsa.decrypt(text_enc_session_key)

        # Decrypt the ciphertext using AES
        text_cipher_aes = AES.new(text_session_key, AES.MODE_EAX, nonce=text_nonce)
        decrypted_text_data = text_cipher_aes.decrypt_and_verify(text_ciphertext, text_tag)
        return decrypted_text_data, text_original_hash

    def get(self, request, id):
        # Ensure the user requesting decryption is superuser
        is_superuser = request.user.is_superuser
        user = request.user
        if not is_superuser:
            messages.error(request, f'Unauthorized User! {str(user)}')
            return HttpResponse('Unauthorized access.', status=403)

        try:
            encrypted_file = get_object_or_404(TextFile, id=id)  # encrypted_file = TextFile.objects.get(id=id)
            text_data, text_hash = self.get_text(id)
            file_data, file_hash = self.get_file(id)

            error_message = None  # Initialize an error message variable
            response = None  # Initialize the response variable

            if not file_data and not text_data:
                error_message = 'FAILED! No data found for decryption.'

            else:
                # Verify hash for file data if it exists
                if file_data:
                    file_hash_calculated = SHA256.new(file_data).digest()
                    if file_hash_calculated != file_hash:
                        error_message = 'FAILED! Integrity check failed for file. File tampered.'

                # Verify hash for text data if it exists
                if text_data:
                    text_hash_calculated = SHA256.new(text_data).digest()
                    if text_hash_calculated != text_hash:
                        error_message = 'FAILED! Integrity check failed for text data. File tampered.'

                # If no integrity check errors, prepare the ZIP archive
                if not error_message:
                    integrity_check = True
                    zip_buffer = io.BytesIO()
                    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                        if file_data:
                            zip_file.writestr(f'TEXTFILE-ID[{encrypted_file.textfile_id}] '
                                              f'<> FILE-NAME-{encrypted_file.textfile_file}',file_data)
                        if text_data:
                            zip_file.writestr(
                                f'RECORD-ID[{encrypted_file.textfile_id}] '
                                f'<> TEXT-NAME-{encrypted_file.textfile_name}.txt', text_data)

                    # Set the appropriate response headers for a ZIP file
                    response = HttpResponse(zip_buffer.getvalue(), content_type='application/zip')
                    response['Content-Disposition'] = (f'attachment; filename="TEXTFILE-ID:{encrypted_file.textfile_id} '
                                                  f'<> DECRYPTED-DATA.zip"')
                    messages.success(request, 'SUCCESS! Decryption successful, check downloads')

                    # Run the class method to capture output
                    decrypt_details_obj = DecryptDetails()
                    user = request.user
                    textfile_id = encrypted_file.textfile_id
                    textfile_name = encrypted_file.textfile_name
                    decrypt_details_obj.save_decrypt_details(user, textfile_id, textfile_name, integrity_check)

            if error_message:
                integrity_check = False
                messages.error(request, error_message)

                # Run the class method to capture output
                decrypt_details_obj = DecryptDetails()
                user = request.user
                textfile_id = encrypted_file.textfile_id
                textfile_name = encrypted_file.textfile_name
                decrypt_details_obj.save_decrypt_details(user, textfile_id, textfile_name, integrity_check)

                return HttpResponse(f'<div class="alert alert-success">Action Unsuccessful!{error_message}</div>')

            if response:
                return response  # Return the response if decryption was successful
        except Exception as e:
            messages.error(request, f'FAILED! Error decrypting data: {str(e)}.')
            return HttpResponse(f'Error decrypting data: {str(e)}', status=500)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class DecryptText(View):
    @staticmethod
    def get(request, id):
        # Ensure the user requesting decryption is superuser
        is_superuser = request.user.is_superuser
        if not is_superuser:
            messages.error(request, f'Unauthorized User! {str(request.user)}')
            return HttpResponse('Unauthorized access.', status=403)

        # Proceed with the decryption
        try:
            # Fetch the encrypted case data from the database
            encrypted_file = get_object_or_404(Text, id=id)  # encrypted_file = TextFile.objects.get(id=id)
            encrypted_data = base64.b64decode(encrypted_file.text_cipher)  # ensure this is decoding correctly

            # Fetch user's private key
            key_pair = KeyPair.objects.get(user=encrypted_file.user)
            private_key = RSA.import_key(key_pair.private_key)

            # Decrypt the data with RSA private key
            cipher_rsa = PKCS1_OAEP.new(private_key)

            # Extract components from the decrypted data with correct lengths for slicing
            key_len = private_key.size_in_bytes()
            enc_session_key = encrypted_data[:key_len]
            nonce = encrypted_data[key_len:key_len + 16]
            tag = encrypted_data[key_len + 16:key_len + 32]
            ciphertext = encrypted_data[key_len + 32:-32]
            original_hash = encrypted_data[-32:]

            # Decrypt the AES session key with RSA private key
            session_key = cipher_rsa.decrypt(enc_session_key)

            # Decrypt the ciphertext using AES
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
            decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

            # Verify the integrity of the decrypted data
            hash_object = SHA256.new()
            hash_object.update(decrypted_data)
            calculated_hash = hash_object.digest()

            if calculated_hash != original_hash:
                messages.error(request, 'FAILED! Integrity Check Status: __ File tampered __')
                integrity_check = False
                # Return the decrypted data
                response = HttpResponse(decrypted_data, content_type='application/octet-stream')
                response['Content-Disposition'] = (f'attachment; filename="TEXT-ID:'
                                                   f'{encrypted_file.text_id} <> TEXT-NAME:'
                                                   f'{encrypted_file.text_name}.txt"')
                # Run the class method to capture output
                decrypt_details_obj = DecryptDetails()
                user = request.user
                text_id = encrypted_file.text_id
                text_name = encrypted_file.text_name
                decrypt_details_obj.save_decrypt_details(user, text_id, text_name, integrity_check)
                time.sleep(.5)
                return redirect('decrypt')
            else:
                integrity_check = True
                messages.success(request, 'SUCCESS! Integrity Check Passed __ File Decrypted And Downloaded __')

                # Return the decrypted data
                response = HttpResponse(decrypted_data, content_type='application/octet-stream')
                response['Content-Disposition'] = (f'attachment; filename="TEXT-ID:'
                                                   f'{encrypted_file.text_id} <> TEXT-NAME:'
                                                   f'{encrypted_file.text_name}.txt"')
                # Run the class method to capture output
                decrypt_details_obj = DecryptDetails()
                user = request.user
                text_id = encrypted_file.text_id
                text_name = encrypted_file.text_name
                decrypt_details_obj.save_decrypt_details(user, text_id, text_name, integrity_check)
                time.sleep(.5)
            return response
        except Exception as e:
            messages.error(request, f'FAILED! Error decrypting data: {str(e)}.')
            return HttpResponse(f'Error decrypting data: {str(e)}', status=500)

            # return HttpResponse(f'Error decrypting data: {str(e)}', status=500)
            # context = {
            #     'encrypted_file': encrypted_file,
            #     'encrypted_data': encrypted_data,
            #     'private_key': private_key,
            #     'cipher_rsa': cipher_rsa,
            #     'key_len': key_len,
            #     'tag': tag,
            #     'nonce': nonce,
            #     'enc_session_key': enc_session_key,
            #     'session_key': session_key,
            #     'cipher_aes': cipher_aes,
            #     'ciphertext': ciphertext,
            #     'decrypted_data': decrypted_data,
            #     'original_hash': original_hash,
            #     'calculated_hash': calculated_hash
            # }
            # return render(request, 'decrypt/view_dec_file_test.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class DecryptFile(View):
    @staticmethod
    def get(request, id):
        # Ensure the user requesting decryption is superuser
        is_superuser = request.user.is_superuser
        if not is_superuser:
            messages.error(request, f'Unauthorized User! {str(request.user)}')
            return HttpResponse(f'Unauthorized Access. {str(request.user)} Forbidden.', status=403)

        # File decryption
        try:
            # get encrypted data RSA private key for decryption
            encrypted_file = get_object_or_404(File, id=id)  # encrypted_file = TextFile.objects.get(id=id)
            private_key = RSA.import_key(KeyPair.objects.get(user=encrypted_file.user).private_key)

            # Extract components from the decrypted data with correct lengths for slicing
            encrypted_data = encrypted_file.file_cipher
            key_len = private_key.size_in_bytes()
            enc_session_key = encrypted_data[:key_len]
            nonce = encrypted_data[key_len:key_len + 16]
            tag = encrypted_data[key_len + 16:key_len + 32]
            ciphertext = encrypted_data[key_len + 32:-32]
            original_hash = encrypted_data[-32:]

            # Decrypt file data
            cipher_rsa = PKCS1_OAEP.new(private_key)
            session_key = cipher_rsa.decrypt(enc_session_key)
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
            decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

            # Verify the integrity of the decrypted data
            hash_object = SHA256.new()
            hash_object.update(decrypted_data)
            calculated_hash = hash_object.digest()

            if calculated_hash != original_hash:
                integrity_check = False
                # Prepare response to download decrypted file
                response = HttpResponse(decrypted_data, content_type='application/octet-stream')
                response['Content-Disposition'] = (f'attachment; filename="FILE-ID:'
                                                   f'{encrypted_file.file_id} <> FILE-NAME:'
                                                   f'{encrypted_file.file_name.name}"')
                # Run the command and capture the output
                decrypt_details_obj = DecryptDetails()
                user = request.user
                file_id = encrypted_file.file_id
                file_name = encrypted_file.file_name.name
                decrypt_details_obj.save_decrypt_details(user, file_id, file_name, integrity_check)
                time.sleep(.5)

                messages.error(request, 'FAILED! Integrity check failed __ File tampered __')
                # return HttpResponse(f'Error decrypting data: {str(e)}', status=500)
            else:
                integrity_check = True
                messages.success(request, f'SUCCESS! Integrity Check Passed __ '
                                          f'{encrypted_file.file_id} File Decrypted And Downloaded __')
                # Prepare response to download decrypted file
                response = HttpResponse(decrypted_data, content_type='application/octet-stream')
                response['Content-Disposition'] = (f'attachment; filename="FILE-ID:'
                                                   f'{encrypted_file.file_id} <> FILE-NAME:'
                                                   f'{encrypted_file.file_name.name}"')
                # Run the command and capture the output
                # Run the class method to capture output
                decrypt_details_obj = DecryptDetails()
                user = request.user
                file_id = encrypted_file.file_id
                file_name = encrypted_file.file_name.name
                decrypt_details_obj.save_decrypt_details(user, file_id, file_name, integrity_check)
                time.sleep(.5)

                return response
        except Exception as e:
            return HttpResponse(f'Error decrypting data: {str(e)}', status=500)

""" END DECRYPT RECORDS """


""" START SEARCH CIPHER RECORDS """

@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class SearchCipherRecords(View):
    @staticmethod
    def get(request):
        user = request.user
        query = request.GET.get('q')
        date = timezone.now()
        try:
            if query:
                files = File.objects.filter(file_id__icontains=query)
                texts = Text.objects.filter(text_id__icontains=query)
                textfiles = TextFile.objects.filter(textfile_id__icontains=query)
                count = files.count() + texts.count() + textfiles.count()

                q_files = File.objects.filter(file_id__icontains=user).count()
                q_texts = Text.objects.filter(text_id__icontains=user).count()
                q_textfiles = TextFile.objects.filter(textfile_id__icontains=user).count()

                context = {
                    'files': files,
                    'texts': texts,
                    'textfiles': textfiles,
                    'q_files': q_files,
                    'q_texts': q_texts,
                    'q_textfiles': q_textfiles,
                    'query': query,
                    'count': count,
                    'user': user,
                    'date': date
                }
                messages.success(request, f'{count} - Matching Data Found')
                return render(request, 'encrypt/search_cipher_records.html', context)
            else:
                q_files = File.objects.filter(file_id__icontains=user).count()
                q_texts = Text.objects.filter(text_id__icontains=user).count()
                q_textfiles = TextFile.objects.filter(textfile_id__icontains=user).count()

                context = {
                    'q_files': q_files,
                    'q_texts': q_texts,
                    'q_textfiles': q_textfiles,
                    'date': date,
                    'user': user
                }
                messages.warning(request, f'Type Record ID In TextBox To Search All Records')
                return render(request, 'encrypt/search_cipher_records.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('search_cipher_records')

""" START ENCRYPT DASHBOARD """

@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class EncryptDashboard(View):
    @staticmethod
    def get(request):
        try:
            date = timezone.now()
            user = request.user
            texts = Text.objects.filter(user=user).count()
            files = File.objects.filter(user=user).count()
            textfiles = TextFile.objects.filter(user=user).count()

            total_files = files + texts + textfiles

            text = Text.objects.filter(user=user).order_by('-id')[:1]
            file = File.objects.filter(user=user).order_by('-id')[:1]
            textfile = TextFile.objects.filter(user_id=user).order_by('-id')[:1]

            key_pair = KeyPair.objects.filter(user=user).count()

            context = {
                'user': user,
                'file': file,
                'text': text,
                'date': date,
                'textfile': textfile,
                'total_files': total_files,
                'key_pair': key_pair,
            }
            return render(request, 'backend/encrypt.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('encrypt')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewCipherRecords(View):
    @staticmethod
    def get(request):
        is_superuser = request.user.is_superuser
        user = request.user
        if is_superuser:
            texts = Text.objects.all().order_by('-id')[:1]
            textfiles = TextFile.objects.all().order_by('-id')[:1]
            files = File.objects.all().order_by('-id')[:1]

            texts_count = Text.objects.all().count()
            textfiles_count = TextFile.objects.all().count()
            files_count = File.objects.all().count()
            encrypted_ciphers_count = texts_count + textfiles_count + files_count
            decrypted_ciphers_count = CipherInfo.objects.all().count()
        else:
            texts = Text.objects.filter(user=user).order_by('-id')[:1]
            files = File.objects.filter(user=user).order_by('-id')[:1]
            textfiles = TextFile.objects.filter(user=user).order_by('-id')[:1]

            texts_count = Text.objects.filter(user=user).count()
            textfiles_count = TextFile.objects.filter(user=user).count()
            files_count = File.objects.filter(user=user).count()
            encrypted_ciphers_count = texts_count + textfiles_count + files_count
            decrypted_ciphers_count = CipherInfo.objects.filter(user=user).count()

        context = {
            'texts_count': texts_count,
            'textfiles_count': textfiles_count,
            'files_count': files_count,
            'encrypted_ciphers_count': encrypted_ciphers_count,
            'decrypted_ciphers_count': decrypted_ciphers_count,
            'files': files,
            'texts': texts,
            'textfiles': textfiles
        }
        return render(request, 'encrypt/view_cipher_records.html', context)

""" END ENCRYPT DASHBOARD """


""" START VIEW CIPHER RECORDS """

@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewCipherText(View):
    @staticmethod
    def get(request, id):
        user = request.user
        try:
            text = get_object_or_404(Text, id=id)
        except Exception as e:
            raise Http404(f'File Details Not Found! Error{str(e)}')
        context = {
            'text': text,
            'user': user
        }
        return render(request, 'encrypt/view_cipher_text.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewCipherTextFileEncrypt(View):
    @staticmethod
    def get(request, id):
        user = request.user
        try:
            textfile = get_object_or_404(TextFile, id=id)
        except Exception as e:
            raise Http404(f'File Details Not Found! Error: {str(e)}')
        context = {
            'textfile': textfile,
            'user': user
        }
        return render(request, 'encrypt/view_cipher_textfile.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewCipherFileEncrypt(View):
    @staticmethod
    def get(request, id):
        user = request.user
        date = timezone.now()
        try:
            file = get_object_or_404(File, id=id)
        except Exception as e:
            raise Http404(f'File Details Not Found! Error: {str(e)}')
        context = {
            'file': file,
            'user': user,
            'date': date
        }
        return render(request, 'encrypt/view_cipher_file.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class CipherFile(View):
    @staticmethod
    def get(request, id):
        user = request.user
        try:
            file = get_object_or_404(File, id=id)
        except Exception as e:
            raise Http404(f'File Details Not Found! Error: {str(e)}')
        context = {
            'file': file,
            'user': user
        }
        return render(request, 'encrypt/cipher_file.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class CipherText(View):
    @staticmethod
    def get(request, id):
        user = request.user
        try:
            text = get_object_or_404(Text, id=id)
        except Exception as e:
            raise Http404(f'File Details Not Found! Error: {str(e)}')
        context = {
            'text': text,
            'user': user
        }
        return render(request, 'encrypt/cipher_text.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class CipherTextFile(View):
    @staticmethod
    def get(request, id):
        user = request.user
        try:
            textfile = get_object_or_404(TextFile, id=id)
        except Exception as e:
            raise Http404(f'File Details Not Found! Error: {str(e)}')
        context = {
            'textfile': textfile,
            'user': user
        }
        return render(request, 'encrypt/cipher_textfile.html', context)

""" END VIEW RECORDS"""


""" START FILTER CASES"""

@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class FilterCipherRecords(View):
    @staticmethod
    def get(request):
        user = request.user
        is_superuser = request.user.is_superuser
        try:
            if is_superuser:
                q_texts = Text.objects.all().count()
                q_files = File.objects.all().count()
                q_textfiles = TextFile.objects.all().count()
            else:
                q_texts = Text.objects.filter(text_id__icontains=user).count()
                q_files = File.objects.filter(file_id__icontains=user).count()
                q_textfiles = TextFile.objects.filter(textfile_id__icontains=user).count()

            context = {
                'user': user,
                'q_texts': q_texts,
                'q_files': q_files,
                'q_textfiles': q_textfiles
            }
            return render(request, 'encrypt/filter_cipher_records.html', context)
        except Exception as e:
            return redirect('filter_cipher_records')

    @staticmethod
    def post(request):
        is_superuser = request.user.is_superuser
        user =  request.user
        try:
            if request.method == 'POST':
                from_date = request.POST.get('from_date')
                to_date = request.POST.get('to_date')

                if is_superuser:
                    filter_files = File.objects.filter(file_date__range=(from_date, to_date))
                    filter_texts = Text.objects.filter(text_date__range=(from_date, to_date))
                    filter_textfiles = TextFile.objects.filter(textfile_date__range=(from_date, to_date))

                    q_texts = Text.objects.all().count()
                    q_files = File.objects.all().count()
                    q_textfiles = TextFile.objects.all().count()
                else:
                    filter_files = File.objects.filter(user=user, file_date__range=(from_date, to_date))
                    filter_texts = Text.objects.filter(user=user, text_date__range=(from_date, to_date))
                    filter_textfiles = TextFile.objects.filter(user=user, textfile_date__range=(from_date, to_date))

                    q_texts = Text.objects.filter(text_id__icontains=user).count()
                    q_files = File.objects.filter(file_id__icontains=user).count()
                    q_textfiles = TextFile.objects.filter(textfile_id__icontains=user).count()

                context = {
                    'files': filter_files,
                    'texts': filter_texts,
                    'textfiles': filter_textfiles,
                    'user': user,
                    'q_texts': q_texts,
                    'q_files': q_files,
                    'q_textfiles': q_textfiles,
                }
                return render(request, 'encrypt/filter_cipher_records.html', context)
            else:
                q_texts = Text.objects.filter(text_id__icontains=user).count()
                q_files = File.objects.filter(file_id__icontains=user).count()
                q_textfiles = TextFile.objects.filter(textfile_id__icontains=user).count()

                context = {
                    'user': user,
                    'q_texts': q_texts,
                    'q_files': q_files,
                    'q_textfiles': q_textfiles
                }
                messages.error(request, f'Select Calender Date To Filter Ciphers.')
                return render(request, 'encrypt/filter_cipher_records.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}!')
            return redirect('filter_cipher_records')

""" END FILTER CASES """


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewDecryptDetails(View):
    @staticmethod
    def get(request):
        is_superuser = request.user.is_superuser
        if is_superuser:
            try:
                decrypt_details = CipherInfo.objects.all().order_by('-id')[:10]
                context = {
                    'decrypt_details': decrypt_details,
                }
                return render(request, 'decrypt/decrypt_details.html', context)
            except Exception as e:
                messages.error(request, f'Error: {str(e)}')
                return render(request, 'decrypt/decrypt_details.html')
        else:
            messages.error(request, f'Error: Unauthorized User {request.user}')
            return redirect('decrypt_details')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewDecryptedDetails(View):
    @staticmethod
    def get(request, id):
        user = request.user
        try:
            info = get_object_or_404(CipherInfo, id=id)
        except Exception as e:
            raise Http404(f'File Details Not Found! Error: {str(e)}')
        context = {
            'info': info,
            'user': user
        }
        return render(request, 'decrypt/view_decrypt_details.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class DeleteDecryptInfo(View):
    @staticmethod
    def get(request, id):
        listing_decrypt_info = get_object_or_404(CipherInfo, id=id)
        return render(request, 'confirm_delete.html', {'object': listing_decrypt_info})

    @staticmethod
    def post(request, id):
        is_superuser = request.user.is_superuser
        listing_decrypt_info = get_object_or_404(CipherInfo, id=id)
        try:
            if is_superuser:
                listing_decrypt_info.delete()
                messages.success(request, 'SUCCESS! Decrypt Information Deleted.')
                return redirect('decrypt_details')
            else:
                messages.error(request, f'FAILED! Unauthorized User: {request.user} Forbidden.')
                return redirect('decrypt_details')
        except Exception as e:
            messages.error(request, f'FAILED! Something Went Wrong. Error: {str(e)}')
            return redirect('decrypt_details')


""" START DELETE RECORDS """


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class DeleteFile(View):
    @staticmethod
    def get(request, id):
        listing_case_file = get_object_or_404(File, id=id)
        return render(request, 'confirm_delete.html', {'object': listing_case_file})

    @staticmethod
    def post(request, id):
        is_superuser = request.user.is_superuser
        listing_case_file = get_object_or_404(File, id=id)
        if request.method == 'POST':
            try:
                if is_superuser:
                    listing_case_file.delete()
                    messages.success(request, 'SUCCESS! File Deleted Successfully')
                    return redirect('decrypt')
                else:
                    messages.error(request, f'FAILED! Unauthorized User: {request.user}')
                    return redirect('encrypt')
            except Exception as e:
                messages.error(request, f'Error: {str(e)}')
                return redirect('decrypt')
        else:
            return render(request, 'confirm_delete.html', {'object': listing_case_file})


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class DeleteText(View):
    @staticmethod
    def get(request, id):
        listing_case_text = get_object_or_404(Text, id=id)
        return render(request, 'confirm_delete.html', {'object': listing_case_text})

    @staticmethod
    def post(request, id):
        is_superuser = request.user.is_superuser
        listing_case_text = get_object_or_404(Text, id=id)
        if request.method == 'POST':
            try:
                if is_superuser:
                    listing_case_text.delete()
                    messages.success(request, 'SUCCESS! File Deleted Successfully')
                    return redirect('decrypt')
                else:
                    messages.error(request, f'FAILED! Unauthorized User: {request.user}')
                    return redirect('encrypt')
            except Exception as e:
                messages.error(request, f'Error: {str(e)}')
                return redirect('decrypt')
        else:
            return render(request, 'confirm_delete.html', {'object': listing_case_text})


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class DeleteTextFile(View):
    @staticmethod
    def get(request, id):
        listing_case_textfile = get_object_or_404(TextFile, id=id)
        return render(request, 'confirm_delete.html', {'object': listing_case_textfile})

    @staticmethod
    def post(request, id):
        is_superuser = request.user.is_superuser
        listing_case_textfile = get_object_or_404(TextFile, id=id)
        if request.method == 'POST':
            try:
                if is_superuser:
                    listing_case_textfile.delete()
                    messages.success(request, 'SUCCESS! File Deleted Successfully')
                    return redirect('decrypt')
                else:
                    messages.error(request, f'FAILED! Unauthorized User: {request.user}')
                    return redirect('encrypt')
            except Exception as e:
                messages.error(request, f'Error: {str(e)}')
                return redirect('decrypt')
        else:
            return render(request, 'confirm_delete.html', {'object': listing_case_textfile})


""" END DELETE RECORDS """

""" START CSV DOWNLOADS"""


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ExportTextsCSV(View):
    @staticmethod
    def get(request):
        try:
            texts = Text.objects.all()
            response = HttpResponse()
            response['Content-Disposition'] = 'attachment; filename=case-texts_export.csv'
            writer = csv.writer(response)
            writer.writerow(['CASE-ID', 'CASE-DATA', 'USER-ID', 'CASE-NAME'])
            fields = texts.values_list('case_id', 'case_data', 'user', 'case_name')
            for text in fields:
                writer.writerow(text)
            return response
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('search_text_cases')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ExportFilesCSV(View):
    @staticmethod
    def get(request):
        try:
            files = File.objects.all()
            response = HttpResponse()
            response['Content-Disposition'] = 'attachment; filename=case-files_export.csv'
            writer = csv.writer(response)
            writer.writerow(['CASE-ID', 'CASE-FILE', 'CASE-DATA', 'USER-ID'])
            fields = files.values_list('case_id', 'case_file', 'case_data', 'user')
            for file in fields:
                writer.writerow(file)
            return response
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('search_file_cases')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ExportTextFilesCSV(View):
    @staticmethod
    def get(request):
        try:
            textfiles = TextFile.objects.all()
            response = HttpResponse()
            response['Content-Disposition'] = 'attachment; filename=case-reports_export.csv'
            writer = csv.writer(response)
            writer.writerow(['CASE-ID', 'CASE-NAME', 'CASE-INFO', 'CASE-FILE', 'CASE-DATA', 'USER-ID'])
            fields = textfiles.values_list('case_id', 'case_name', 'case_info', 'case_file', 'case_data', 'user')
            for textfile in fields:
                writer.writerow(textfile)
            return response
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('search_report_cases')


""" END CSV DOWNLOADS"""

""" REDUNDANT CODE START """


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def update(request, id):
    is_superuser = request.user.is_superuser
    if is_superuser:
        listing = get_object_or_404(Text, id=id)
        form = TextForm(instance=listing)
        if request.method == 'POST':
            form = TextForm(request.POST, instance=listing)
            if form.is_valid():
                messages.success(request, 'SUCCESS! File Updated Successfully.')
                form.save()
                return redirect('decrypt')
            else:
                messages.error(request, 'FAILED! Something Went Wrong.')
                context = {
                    'form': form
                }
                return render(request, 'decrypt/update.html', context)
        context = {
            'form': form
        }
        return render(request, 'decrypt/update.html', context)
    elif not is_superuser:
        user = request.user
        messages.error(request, f'FAILED! Unauthorized User: {user}')
        return redirect('encrypt')
    else:
        return redirect('decrypt')


""" REDUNDANT CODE END """