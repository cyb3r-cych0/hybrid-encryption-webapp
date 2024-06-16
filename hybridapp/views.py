import base64
import csv
import io
import time
import zipfile
import subprocess

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

from .forms import TextForm, FileUploadForm, RegisterForm, TextFileForm
from .models import KeyPair, File, Text, TextFile, DecryptInfo

""" START USER INFO """


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewUsersBackend(View):
    @staticmethod
    def get(request):
        users = User.objects.all()
        user = request.user
        context = {
            'users': users,
            'user': user
        }
        return render(request, 'backend/view_users_backend.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class UserDetailsBackend(View):
    @staticmethod
    def get(request, id):
        user = request.user
        user_details = get_object_or_404(User, id=id)
        try:
            texts = Text.objects.filter(user=user_details).count()
            files = File.objects.filter(user=user_details).count()
            textfiles = TextFile.objects.filter(user=user_details).count()
            total_files = files + texts + textfiles

            text = Text.objects.filter(user=user_details).order_by('-id')[:1]
            file = File.objects.filter(user=user_details).order_by('-id')[:1]
            textfile = TextFile.objects.filter(user=user_details).order_by('-id')[:1]
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            raise Http404(f'User Details Not Found! {str(e)}')
        context = {
            'user_details': user_details,
            'total_files': total_files,
            'user': user,
            'file': file,
            'text': text,
            'textfile': textfile
        }
        return render(request, 'backend/user_details_backend.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class UserCasesBackend(View):
    @staticmethod
    def get(request, id):
        user = request.user
        user_details = get_object_or_404(User, id=id)
        try:
            text = Text.objects.filter(user=user_details).order_by('-id')
            file = File.objects.filter(user=user_details).order_by('-id')
            textfile = TextFile.objects.filter(user=user_details).order_by('-id')
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            raise Http404(f'User Details Not Found! {str(e)}')
        context = {
            'user_details': user_details,
            'user': user,
            'file': file,
            'text': text,
            'textfile': textfile
        }
        return render(request, 'backend/user_cases_backend.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class FilterUserCases(View):
    @staticmethod
    def post(request, id):
        is_superuser = request.user.is_superuser
        user_details = get_object_or_404(User, id=id)
        user = request.user
        try:
            from_date = request.POST.get('from_date')
            to_date = request.POST.get('to_date')

            search_file_result = File.objects.filter(user=user_details, case_date__range=[from_date, to_date])
            search_text_result = Text.objects.filter(user=user_details, case_date__range=[from_date, to_date])
            search_textfile_result = TextFile.objects.filter(user=user_details, case_date__range=[from_date, to_date])

            # Extract date values from the filtered query sets
            date_values = [item.case_date for item in search_textfile_result]
            date = date_values[0] if date_values else None

            context = {
                'files': search_file_result,
                'texts': search_text_result,
                'textfiles': search_textfile_result,
                'date_values': date_values,
                'date': date,
                'is_superuser': is_superuser,
                'user_details': user_details,
                'user': user
            }
            return render(request, 'backend/filter_user_cases.html', context)
        except Exception as e:
            messages.error(request, f'Error: Please Choose Valid Date To Filter!')
            context = {
                'is_superuser': is_superuser,
                'user_details': user_details,
                'user': user
            }
            return render(request, 'backend/filter_user_cases.html', context)

    @staticmethod
    def get(request, id):
        is_superuser = request.user.is_superuser
        user_details = get_object_or_404(User, id=id)
        user = request.user
        messages.error(request, f'Select Calender Date To Filter Searched Cases.')
        context = {
            'is_superuser': is_superuser,
            'user_details': user_details,
            'user': user
        }
        return render(request, 'backend/filter_user_cases.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class SearchUsers(View):
    @staticmethod
    def get(request):
        user = request.user
        query = request.GET.get('q')
        try:
            if query:
                users = User.objects.filter(username__icontains=query)
                count = users.count()
                context = {
                    'user': user,
                    'users': users,
                    'count': count
                }
                messages.success(request, f'{count} - Matching Cases Found')
            else:
                context = {'user': user}  # Empty context if no query provided
                messages.error(request, f'Type Case ID In TextBox To Search All Cases')
            return render(request, 'backend/search_users.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('search_users')


""" END USER INFO """

""" START ENCRYPT CASES """


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class EncryptTextFile(View):
    @staticmethod
    def get(request):
        form = TextFileForm()
        context = {
            'form': form
        }
        return render(request, 'encrypt/encrypt_case.html', context)

    @staticmethod
    def post(request):
        form = TextFileForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                case_id = form.cleaned_data['case_id']
                case_name = form.cleaned_data['case_name']
                case_info = form.cleaned_data['case_info'].encode()
                case_data = form.cleaned_data['case_file'].read()
                user = request.user

                # Fetch user's RSA public key
                key_pair = KeyPair.objects.get(user=user)
                public_key = RSA.import_key(key_pair.public_key)

                # Hash object for file verification
                file_hash_object = SHA256.new()
                file_hash_object.update(case_data)
                file_original_hash = file_hash_object.digest()

                text_hash_object = SHA256.new()
                text_hash_object.update(case_info)
                text_original_hash = text_hash_object.digest()

                # Encrypt file data
                session_key = get_random_bytes(16)
                cipher_rsa = PKCS1_OAEP.new(public_key)
                enc_session_key = cipher_rsa.encrypt(session_key)
                cipher_aes = AES.new(session_key, AES.MODE_EAX)
                cipherfile, tag = cipher_aes.encrypt_and_digest(case_data)

                # Generate AES, pad & encrypted text data
                text_cipher_rsa = PKCS1_OAEP.new(public_key)
                text_session_key = get_random_bytes(16)
                text_cipher_aes = AES.new(text_session_key, AES.MODE_EAX)
                text_ciphertext, text_tag = text_cipher_aes.encrypt_and_digest(case_info)
                text_enc_session_key = text_cipher_rsa.encrypt(text_session_key)

                # Store encrypted data in database
                encrypted_file = enc_session_key + cipher_aes.nonce + tag + cipherfile + file_original_hash
                encrypted_text = base64.b64encode(
                    text_enc_session_key + text_cipher_aes.nonce + text_tag + text_ciphertext + text_original_hash).decode(
                    'utf-8')

                # Save encrypted case data to the database
                new_case = TextFile.objects.create(
                    case_id=case_id,
                    case_name=case_name,
                    case_info=encrypted_text,
                    case_file=form.cleaned_data['case_file'],
                    case_data=encrypted_file,
                    user=user
                )

                # software feedback
                if new_case:
                    messages.success(request, 'SUCCESS! Case TextFile Encrypted __ Scrambled Data Saved __')
                    return redirect('encrypt')
            except Exception as e:
                messages.error(request, f'FAILED! Error Encrypting TextFile __ Error: {str(e)} __')
                return redirect('encrypt_case')
        context = {
            'form': form
        }
        return render(request, 'encrypt/encrypt_case.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class EncryptText(View):
    @staticmethod
    def get(request):
        form = TextForm()
        context = {
            'form': form
        }
        return render(request, 'encrypt/encrypt_case_data.html', context)

    @staticmethod
    def post(request):
        form = TextForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                case_id = form.cleaned_data['case_id']
                case_name = form.cleaned_data['case_name']
                case_data = form.cleaned_data['case_data'].encode()
                user = request.user

                # Fetch user's RSA public key
                key_pair = KeyPair.objects.get(user=user)
                public_key = RSA.import_key(key_pair.public_key)

                # Hash object for verification
                hash_object = SHA256.new()
                hash_object.update(case_data)
                original_hash = hash_object.digest()

                # Generate AES, pad & encrypted data
                cipher_rsa = PKCS1_OAEP.new(public_key)
                session_key = get_random_bytes(16)
                cipher_aes = AES.new(session_key, AES.MODE_EAX)
                ciphertext, tag = cipher_aes.encrypt_and_digest(case_data)
                enc_session_key = cipher_rsa.encrypt(session_key)
                encrypted_data = base64.b64encode(
                    enc_session_key + cipher_aes.nonce + tag + ciphertext + original_hash).decode('utf-8')

                # Save encrypted case data to the database
                new_case = Text.objects.create(
                    case_id=case_id,
                    case_name=case_name,
                    case_data=encrypted_data,
                    user=user
                )

                # software feedback
                if new_case:
                    messages.success(request, 'SUCCESS! Case Text Encrypted __ Scrambled Data Saved __')
                    return redirect('encrypt')
            except Exception as e:
                messages.error(request, f'FAILED! Error Encrypting Text __ Error: {str(e)} __')
                return redirect('encrypt_case_data')
        context = {
            'form': form
        }
        return render(request, 'encrypt/encrypt_case_data.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class EncryptFile(View):
    @staticmethod
    def get(request):
        form = FileUploadForm()
        context = {
            'form': form
        }
        return render(request, 'encrypt/upload_file.html', context)

    @staticmethod
    def post(request):
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                user = request.user
                case_id = form.cleaned_data['case_id']
                case_data = form.cleaned_data['case_file'].read()

                # Fetch user's RSA public key
                key_pair = KeyPair.objects.get(user=user)
                public_key = RSA.import_key(key_pair.public_key)

                # Hash object for verification
                hash_object = SHA256.new()
                hash_object.update(case_data)
                original_hash = hash_object.digest()

                # Encrypt file data
                session_key = get_random_bytes(16)
                cipher_rsa = PKCS1_OAEP.new(public_key)
                enc_session_key = cipher_rsa.encrypt(session_key)
                cipher_aes = AES.new(session_key, AES.MODE_EAX)
                ciphertext, tag = cipher_aes.encrypt_and_digest(case_data)

                # Store encrypted data in database
                encrypted_data = enc_session_key + cipher_aes.nonce + tag + ciphertext + original_hash
                new_case = File.objects.create(user=user, case_id=case_id, case_file=form.cleaned_data['case_file'],
                                               case_data=encrypted_data)

                # software feedback
                if new_case:
                    messages.success(request, 'SUCCESS! Case File Encrypted __ Scrambled Data Saved __')
                    return redirect('encrypt')
            except Exception as e:
                messages.error(request, f'FAILED! Error Encrypting File __ Error: {str(e)} __')
                return redirect('upload_file')
        context = {
            'form': form
        }
        return render(request, 'encrypt/upload_file.html', context)


""" END ENCRYPT CASES """

""" START DECRYPT CASES """


class DecryptDetails:
    @staticmethod
    def save_decrypt_details(user, case_id, file_name, integrity_check):
        # Save the decrypt details to the database
        DecryptInfo.objects.create(
            user=user,
            case_id=case_id,
            file_name=file_name,
            integrity_check=integrity_check
        )


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class DecryptTextFile(View):
    @staticmethod
    def get_file(id):
        # get encrypted data RSA private key for decryption
        encrypted_file = get_object_or_404(TextFile, id=id)  # encrypted_file = TextFile.objects.get(id=id)
        private_key = RSA.import_key(KeyPair.objects.get(user=encrypted_file.user_id).private_key)

        # Extract components from the decrypted data with correct lengths for slicing
        encrypted_file_data = encrypted_file.case_data
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
        encrypted_file = get_object_or_404(TextFile, id=id)  # encrypted_file = TextFile.objects.get(id=id)

        # Fetch user's private key
        key_pair = KeyPair.objects.get(user=encrypted_file.user_id)
        private_ky = RSA.import_key(key_pair.private_key)

        text_cipher_rsa = PKCS1_OAEP.new(private_ky)
        encrypted_text_data = base64.b64decode(encrypted_file.case_info)  # ensure this is decoding correctly

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
                            zip_file.writestr(f'CASE-ID[{encrypted_file.case_id}] <> FILE-NAME-{encrypted_file.case_file}',
                                              file_data)
                        if text_data:
                            zip_file.writestr(
                                f'CASE-ID[{encrypted_file.case_id}] <> TEXT-NAME-{encrypted_file.case_name}.txt', text_data)

                    # Set the appropriate response headers for a ZIP file
                    response = HttpResponse(zip_buffer.getvalue(), content_type='application/zip')
                    response[
                        'Content-Disposition'] = f'attachment; filename="CASE-ID:{encrypted_file.case_id} <> DECRYPTED-DATA.zip"'
                    messages.success(request, 'SUCCESS! Decryption successful, check downloads')

                    # Run the class method to capture output
                    decrypt_details_obj = DecryptDetails()
                    user = request.user
                    case_id = encrypted_file.case_id
                    file_name = encrypted_file.case_name
                    decrypt_details_obj.save_decrypt_details(user, case_id, file_name, integrity_check)

            if error_message:
                integrity_check = False
                messages.error(request, error_message)

                # Run the class method to capture output
                decrypt_details_obj = DecryptDetails()
                user = request.user
                case_id = encrypted_file.case_id
                file_name = encrypted_file.case_name
                decrypt_details_obj.save_decrypt_details(user, case_id, file_name, integrity_check)

                return HttpResponseRedirect(reverse('decrypt'))

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
            encrypted_data = base64.b64decode(encrypted_file.case_data)  # ensure this is decoding correctly

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
                response['Content-Disposition'] = (f'attachment; filename="CASE-ID:'
                                                   f'{encrypted_file.case_id} <> FILE-NAME:'
                                                   f'{encrypted_file.case_name}.txt"')
                # Run the class method to capture output
                decrypt_details_obj = DecryptDetails()
                user = request.user
                case_id = encrypted_file.case_id
                file_name = encrypted_file.case_name
                decrypt_details_obj.save_decrypt_details(user, case_id, file_name, integrity_check)
                time.sleep(.5)
                return redirect('decrypt')
            else:
                integrity_check = True
                messages.success(request, 'SUCCESS! Integrity Check Passed __ File Decrypted And Downloaded __')

                # Return the decrypted data
                response = HttpResponse(decrypted_data, content_type='application/octet-stream')
                response['Content-Disposition'] = (f'attachment; filename="CASE-ID:'
                                                   f'{encrypted_file.case_id} <> FILE-NAME:'
                                                   f'{encrypted_file.case_name}.txt"')
                # Run the class method to capture output
                decrypt_details_obj = DecryptDetails()
                user = request.user
                case_id = encrypted_file.case_id
                file_name = encrypted_file.case_name
                decrypt_details_obj.save_decrypt_details(user, case_id, file_name, integrity_check)
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
            # return render(request, 'decrypt/view_dec_file.html', context)


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
            encrypted_data = encrypted_file.case_data
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
                response['Content-Disposition'] = (f'attachment; filename="CASE-ID:'
                                                   f'{encrypted_file.case_id} <> FILE-NAME:'
                                                   f'{encrypted_file.case_file.name}"')
                # Run the command and capture the output
                decrypt_details_obj = DecryptDetails()
                user = request.user
                case_id = encrypted_file.case_id
                file_name = encrypted_file.case_file.name
                decrypt_details_obj.save_decrypt_details(user, case_id, file_name, integrity_check)
                time.sleep(.5)

                e = messages.error(request, 'FAILED! Integrity check failed __ File tampered __')
                return HttpResponse(f'Error decrypting data: {str(e)}', status=500)
            else:
                integrity_check = True
                messages.success(request, f'SUCCESS! Integrity Check Passed __ '
                                          f'{encrypted_file.case_id} File Decrypted And Downloaded __')
                # Prepare response to download decrypted file
                response = HttpResponse(decrypted_data, content_type='application/octet-stream')
                response['Content-Disposition'] = (f'attachment; filename="CASE-ID:'
                                                   f'{encrypted_file.case_id} <> FILE-NAME:'
                                                   f'{encrypted_file.case_file.name}"')
                # Run the command and capture the output
                # Run the class method to capture output
                decrypt_details_obj = DecryptDetails()
                user = request.user
                case_id = encrypted_file.case_id
                file_name = encrypted_file.case_file.name
                decrypt_details_obj.save_decrypt_details(user, case_id, file_name, integrity_check)
                time.sleep(.5)

                return response
        except Exception as e:
            return HttpResponse(f'Error decrypting data: {str(e)}', status=500)


""" END DECRYPT CASES """

""" START SEARCH CASE RECORDS """


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class SearchCasesBackend(View):
    @staticmethod
    def get(request):
        user = request.user
        query = request.GET.get('q')
        try:
            if query:
                # Perform search in both tables
                case_files = File.objects.filter(case_id__icontains=query)
                case_texts = Text.objects.filter(case_id__icontains=query)
                case_textfiles = TextFile.objects.filter(case_id__icontains=query)
                count = case_files.count() + case_texts.count() + case_textfiles.count()
                context = {
                    'case_files': case_files,
                    'case_texts': case_texts,
                    'case_textfiles': case_textfiles,
                    'query': query,
                    'count': count,
                    'user': user
                }
                messages.success(request, f'{count} - Matching Cases Found')
            else:
                context = {'user': user}  # Empty context if no query provided
                messages.error(request, f'Type Case ID In TextBox To Search All Cases')
            return render(request, 'backend/search_results.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('search_results')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class SearchCasesEncrypt(View):
    @staticmethod
    def get(request):
        user = request.user
        query = request.GET.get('q')
        try:
            if query:
                # Perform search in both tables
                case_files = File.objects.filter(case_id__icontains=query)
                case_texts = Text.objects.filter(case_id__icontains=query)
                case_textfiles = TextFile.objects.filter(case_id__icontains=query)
                count = case_files.count() + case_texts.count() + case_textfiles.count()
                context = {
                    'case_files': case_files,
                    'case_texts': case_texts,
                    'case_textfiles': case_textfiles,
                    'query': query,
                    'count': count,
                    'user': user
                }
                messages.success(request, f'{count} - Matching Cases Found')
            else:
                context = {'user': user}  # Empty context if no query provided
                messages.error(request, f'Type Case ID In TextBox To Search All Cases')
            return render(request, 'encrypt/search_cases_encrypt.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('search_cases_encrypt')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class SearchCasesDecrypt(View):
    @staticmethod
    def get(request):
        user = request.user
        query = request.GET.get('q')
        try:
            if query:
                # Perform search in both tables
                case_files = File.objects.filter(case_id__icontains=query)
                case_texts = Text.objects.filter(case_id__icontains=query)
                case_textfiles = TextFile.objects.filter(case_id__icontains=query)
                count = case_files.count() + case_texts.count() + case_textfiles.count()
                context = {
                    'case_files': case_files,
                    'case_texts': case_texts,
                    'case_textfiles': case_textfiles,
                    'query': query,
                    'count': count,
                    'user': user
                }
                messages.success(request, f'{count} - Matching Cases Found')
            else:
                context = {'user': user}  # Empty context if no query provided
                messages.error(request, f'Type Case ID In TextBox To Search All Cases')
            return render(request, 'decrypt/search_cases_decrypt.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('search_cases_decrypt')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class SearchTextDecrypt(View):
    @staticmethod
    def get(request):
        user = request.user
        query = request.GET.get('caseID')
        try:
            if query:
                # Perform search in both tables
                texts = Text.objects.filter(case_id__icontains=query)
                count = texts.count()
                context = {
                    'cases': texts,
                    'query': query,
                    'count': count,
                    'user': user
                }
                messages.success(request, f'{count} - Matching Cases Found')
            else:
                context = {'user': user}  # Empty context if no query provided
                messages.error(request, f'Type Case ID In TextBox To Search Text Cases')
            return render(request, 'decrypt/search_text_cases.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('search_text_cases')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class SearchFileDecrypt(View):
    @staticmethod
    def get(request):
        user = request.user
        query = request.GET.get('case_id')
        try:
            if query:
                # Perform search in both tables
                files = File.objects.filter(case_id__icontains=query)
                count = files.count()
                context = {
                    'files': files,
                    'query': query,
                    'count': count,
                    'user': user
                }
                messages.success(request, f'{count} - Matching Cases Found')
            else:
                context = {'user': user}  # Empty context if no query provided
                messages.error(request, f'Type Case ID In TextBox To Search File Cases!')
            return render(request, 'decrypt/search_file_cases.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}!')
            return redirect('search_file_cases')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class SearchTextFileDecrypt(View):
    @staticmethod
    def get(request):
        user = request.user
        query = request.GET.get('case_id')
        try:
            if query:
                # Perform search in both tables
                textfiles = TextFile.objects.filter(case_id__icontains=query)
                count = textfiles.count()
                context = {
                    'textfiles': textfiles,
                    'query': query,
                    'count': count,
                    'user': user
                }
                messages.success(request, f'{count} - Matching Cases Found')
            else:
                context = {'user': user}  # Empty context if no query provided
                messages.error(request, f'Type Case ID In TextBox To Search Report Cases!')
            return render(request, 'decrypt/search_report_cases.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}!')
            return redirect('search_report_cases')


""" END SEARCH CASE RECORDS """


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class EncryptDashboard(View):
    @staticmethod
    def get(request):
        try:
            user = request.user
            texts = Text.objects.filter(user=user).count()
            files = File.objects.filter(user=user).count()
            textfiles = TextFile.objects.filter(user=user).count()

            total_files = files + texts + textfiles

            text = Text.objects.filter(user=user).order_by('-id')[:1]
            file = File.objects.filter(user=user).order_by('-id')[:1]
            textfile = TextFile.objects.filter(user_id=user).order_by('-id')[:1]

            context = {
                'user': user,
                'file': file,
                'text': text,
                'textfile': textfile,
                'total_files': total_files
            }
            return render(request, 'backend/encrypt.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('encrypt')


# View Encrypted text Files (backend)
@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewTextEncrypt(View):
    @staticmethod
    def get(request, id):
        user = request.user
        try:
            file = get_object_or_404(Text, id=id)
        except Exception as e:
            raise Http404(f'File Details Not Found! Error{str(e)}')
        context = {
            'file': file,
            'user': user
        }
        return render(request, 'encrypt/view_file.html', context)


# view encrypted text and files
@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewCasesEncrypt(View):
    @staticmethod
    def get(request):
        user = request.user
        texts = Text.objects.filter(user=user).order_by('-id')[:10]
        files = File.objects.filter(user=user).order_by('-id')[:10]
        textfiles = TextFile.objects.filter(user=user).order_by('-id')[:10]

        context = {
            'files': files,
            'texts': texts,
            'textfiles': textfiles
        }
        return render(request, 'encrypt/view_files.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewTextBackend(View):
    @staticmethod
    def get(request, id):
        user = request.user
        try:
            file = get_object_or_404(Text, id=id)
        except Exception as e:
            raise Http404(f'File Details Not Found! Error:{str(e)}')
        context = {
            'file': file,
            'user': user
        }
        return render(request, 'backend/view_file_backend.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewTextDecrypt(View):
    @staticmethod
    def get(request, id):
        user = request.user
        try:
            file = get_object_or_404(Text, id=id)
        except Exception as e:
            raise Http404(f'File Details Not Found! Error: {str(e)}')
        context = {
            'file': file,
            'user': user
        }
        return render(request, 'decrypt/view_file_decrypt.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewTextFileBackend(View):
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
        return render(request, 'backend/view_report_backend.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewTextFileDecrypt(View):
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
        return render(request, 'decrypt/view_report_decrypt.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewTextFileEncrypt(View):
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
        return render(request, 'encrypt/view_report_encrypt.html', context)


# View Encrypted Data Files (backend)
@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewFileEncrypt(View):
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
        return render(request, 'encrypt/view_data.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewFileBackend(View):
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
        return render(request, 'backend/view_data_backend.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewFileDecrypt(View):
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
        return render(request, 'decrypt/view_data_decrypt.html', context)


# Register New User
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
        if form.is_valid():
            form.save()
            messages.success(request, 'SUCCESS! User Registered __ Encryption Keys Generated __ ')
            return redirect('login')
        else:
            messages.error(request, 'FAILED! Registration Unsuccessful __ Error: Form is not valid __')
            context = {
                'form': form
            }
            return render(request, 'registration/register_user.html', context)


# Decrypt Dashboard (backend)
@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class DecryptDashboard(View):
    @staticmethod
    def get(request):
        is_superuser = request.user.is_superuser

        text = Text.objects.all().order_by('-id')[:1]
        file = File.objects.all().order_by('-id')[:1]
        textfile = TextFile.objects.all().order_by('-id')[:1]
        texts = Text.objects.all().count()
        files = File.objects.all().count()
        textfiles = TextFile.objects.all().count()
        decrypt_details = DecryptInfo.objects.all().count()
        case_files = files + texts + textfiles

        context = {
            'is_superuser': is_superuser,
            'case_files': case_files,
            'text': text,
            'file': file,
            'textfile': textfile,
            'decrypt_details': decrypt_details
        }
        return render(request, 'backend/decrypt.html', context)


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewCasesDecrypt(View):
    @staticmethod
    def get(request):
        is_superuser = request.user.is_superuser
        if is_superuser:
            try:
                texts = Text.objects.all().order_by('-id')[:10]
                files = File.objects.all().order_by('-id')[:10]
                textfiles = TextFile.objects.all().order_by('-id')[:10]
                context = {
                    'texts': texts,
                    'files': files,
                    'textfiles': textfiles
                }
                return render(request, 'decrypt/view_all.html', context)
            except Exception as e:
                messages.error(request, f'Error: {str(e)}')
                return render(request, 'decrypt/view_all.html')
        else:
            messages.error(request, f'Error: Unauthorized User {request.user}')
            return redirect('view_all')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewCasesBackend(View):
    @staticmethod
    def get(request):
        user = request.user
        try:
            files = Text.objects.all().order_by('-id')[:10] or []
            f_files = File.objects.all().order_by('-id')[:10] or []
            textfiles = TextFile.objects.all().order_by('-id')[:10] or []

            context = {
                'files': files,
                'f_files': f_files,
                'textfiles': textfiles,
                'user': user
            }
            return render(request, 'backend/view_all_backend.html', context)
        except Exception as e:
            messages.error(request, f'No Files Found! __ Error: {str(e)}')
            return render(request, 'backend/view_all_backend.html', {'user': user})


# Frontend
class FrontEnd(View):
    @staticmethod
    def get(request):
        return render(request, 'frontend.html')


# Backend
@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class BackEnd(View):
    @staticmethod
    def get(request):
        return render(request, 'backend.html')


""" START DELETE CASE RECORDS """


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


""" END DELETE CASE RECORDS """

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

""" START FILTER CASES"""


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class FilterTextFilesDecrypt(View):
    @staticmethod
    def get(request):
        is_superuser = request.user.is_superuser
        context = {
            'is_superuser': is_superuser
        }
        return render(request, 'decrypt/filter_reports.html', context)

    @staticmethod
    def post(request):
        is_superuser = request.user.is_superuser
        try:
            from_date = request.POST.get('from_date')
            to_date = request.POST.get('to_date')
            search_result = TextFile.objects.raw(
                'select id, case_id, case_name, case_info, case_file, case_data from hybridapp_textfile where case_date between "' + from_date + '" and "' + to_date + '"')

            # Extract date values from the raw_queryset
            date_values = [item.case_date for item in search_result]
            for date_value in date_values:
                date = date_value
            context = {
                'reports': search_result,
                'date_values': date_values,
                'date': date,
                'is_superuser': is_superuser
            }
            return render(request, 'decrypt/filter_reports.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            return redirect('filter_reports')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class FilterTextsDecrypt(View):
    @staticmethod
    def get(request):
        is_superuser = request.user.is_superuser
        context = {
            'is_superuser': is_superuser
        }
        return render(request, 'decrypt/filter_texts.html', context)

    @staticmethod
    def post(request):
        is_superuser = request.user.is_superuser
        try:
            if request.method == 'POST':
                from_date = request.POST.get('from_date')
                to_date = request.POST.get('to_date')
                search_result = Text.objects.raw(
                    'select id, case_id, case_name, case_data from hybridapp_text where case_date between "' + from_date + '" and "' + to_date + '"')

                # Extract date values from the raw_queryset
                date_values = [item.case_date for item in search_result]
                for date_value in date_values:
                    date = date_value
                context = {
                    'texts': search_result,
                    'date_values': date_values,
                    'date': date,
                    'is_superuser': is_superuser
                }
                return render(request, 'decrypt/filter_texts.html', context)
            else:
                messages.error(request, f'Select Calender Date To Filter Searched Texts.')
                context = {
                    'is_superuser': is_superuser
                }
                return render(request, 'decrypt/filter_texts.html', context)
        except Exception as e:
            messages.error(request, f'Error:. {str(e)}')
            return redirect('filter_texts')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class FilterFilesDecrypt(View):
    @staticmethod
    def get(request):
        is_superuser = request.user.is_superuser
        context = {
            'is_superuser': is_superuser
        }
        return render(request, 'decrypt/filter_files.html', context)

    @staticmethod
    def post(request):
        is_superuser = request.user.is_superuser
        try:
            if request.method == 'POST':
                from_date = request.POST.get('from_date')
                to_date = request.POST.get('to_date')
                search_result = File.objects.raw(
                    'select id, case_id, case_file, case_data from hybridapp_file where case_date between "' + from_date + '" and "' + to_date + '"')

                # Extract date values from the raw_queryset
                date_values = [item.case_date for item in search_result]
                for date_value in date_values:
                    date = date_value
                context = {
                    'files': search_result,
                    'date_values': date_values,
                    'date': date,
                    'is_superuser': is_superuser
                }
                return render(request, 'decrypt/filter_files.html', context)
            else:
                messages.error(request, f'Select Calender Date To Filter Searched Files.')
                context = {
                    'is_superuser': is_superuser
                }
                return render(request, 'decrypt/filter_files.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}!')
            return redirect('filter_files')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class FilterCasesBackend(View):
    @staticmethod
    def get(request):
        is_superuser = request.user.is_superuser
        context = {
            'is_superuser': is_superuser
        }
        return render(request, 'backend/filter_cases.html', context)

    @staticmethod
    def post(request):
        is_superuser = request.user.is_superuser
        try:
            if request.method == 'POST':
                from_date = request.POST.get('from_date')
                to_date = request.POST.get('to_date')

                search_file_result = File.objects.raw(
                    'select id, case_id, case_file, case_data from hybridapp_file where case_date between "' + from_date + '" and "' + to_date + '"')
                search_text_result = Text.objects.raw(
                    'select id, case_id, case_name, case_data from hybridapp_text where case_date between "' + from_date + '" and "' + to_date + '"')
                search_textfile_result = TextFile.objects.raw(
                    'select id, case_id, case_name, case_info, case_file, case_data from hybridapp_textfile where case_date between "' + from_date + '" and "' + to_date + '"')

                # Extract date values from the raw_queryset
                date_values = [item.case_date for item in search_textfile_result]
                for date_value in date_values:
                    date = date_value
                context = {
                    'files': search_file_result,
                    'texts': search_text_result,
                    'textfiles': search_textfile_result,
                    'date_values': date_values,
                    'date': date,
                    'is_superuser': is_superuser
                }
                return render(request, 'backend/filter_cases.html', context)
            else:
                messages.error(request, f'Select Calender Date To Filter Searched Cases.')
                context = {
                    'is_superuser': is_superuser
                }
                return render(request, 'backend/filter_cases.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}!')
            return redirect('filter_cases')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class FilterCasesEncrypt(View):
    @staticmethod
    def get(request):
        is_superuser = request.user.is_superuser
        context = {
            'is_superuser': is_superuser
        }
        return render(request, 'encrypt/filter_cases_encrypt.html', context)

    @staticmethod
    def post(request):
        is_superuser = request.user.is_superuser
        try:
            if request.method == 'POST':
                from_date = request.POST.get('from_date')
                to_date = request.POST.get('to_date')

                search_file_result = File.objects.raw(
                    'select id, case_id, case_file, case_data from hybridapp_file where case_date between "' + from_date + '" and "' + to_date + '"')
                search_text_result = Text.objects.raw(
                    'select id, case_id, case_name, case_data from hybridapp_text where case_date between "' + from_date + '" and "' + to_date + '"')
                search_textfile_result = TextFile.objects.raw(
                    'select id, case_id, case_name, case_info, case_file, case_data from hybridapp_textfile where case_date between "' + from_date + '" and "' + to_date + '"')

                # Extract date values from the raw_queryset
                date_values = [item.case_date for item in search_textfile_result]
                for date_value in date_values:
                    date = date_value
                context = {
                    'files': search_file_result,
                    'texts': search_text_result,
                    'textfiles': search_textfile_result,
                    'date_values': date_values,
                    'date': date,
                    'is_superuser': is_superuser
                }
                return render(request, 'encrypt/filter_cases_encrypt.html', context)
            else:
                messages.error(request, f'Select Calender Date To Filter Searched Cases.')
                context = {
                    'is_superuser': is_superuser
                }
                return render(request, 'encrypt/filter_cases_encrypt.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}!')
            return redirect('filter_cases_encrypt')


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class FilterCasesDecrypt(View):
    @staticmethod
    def get(request):
        is_superuser = request.user.is_superuser
        context = {
            'is_superuser': is_superuser
        }
        return render(request, 'decrypt/filter_cases_decrypt.html', context)

    @staticmethod
    def post(request):
        is_superuser = request.user.is_superuser
        try:
            if request.method == 'POST':
                from_date = request.POST.get('from_date')
                to_date = request.POST.get('to_date')

                search_file_result = File.objects.raw(
                    'select id, case_id, case_file, case_data from hybridapp_file where case_date between "' + from_date + '" and "' + to_date + '"')
                search_text_result = Text.objects.raw(
                    'select id, case_id, case_name, case_data from hybridapp_text where case_date between "' + from_date + '" and "' + to_date + '"')
                search_textfile_result = TextFile.objects.raw(
                    'select id, case_id, case_name, case_info, case_file, case_data from hybridapp_textfile where case_date between "' + from_date + '" and "' + to_date + '"')

                # Extract date values from the raw_queryset
                date_values = [item.case_date for item in search_textfile_result]
                for date_value in date_values:
                    date = date_value
                context = {
                    'files': search_file_result,
                    'texts': search_text_result,
                    'textfiles': search_textfile_result,
                    'date_values': date_values,
                    'date': date,
                    'is_superuser': is_superuser
                }
                return render(request, 'decrypt/filter_cases_decrypt.html', context)
            else:
                messages.error(request, f'Select Calender Date To Filter Searched Cases.')
                context = {
                    'is_superuser': is_superuser
                }
                return render(request, 'decrypt/filter_cases_decrypt.html', context)
        except Exception as e:
            messages.error(request, f'Error: {str(e)}!')
            return redirect('filter_cases_decrypt')


""" END FILTER CASES """

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


@method_decorator(login_required(login_url='login'), name='dispatch')
@method_decorator(cache_control(no_cache=True, must_revalidate=True, no_store=True), name='dispatch')
class ViewDecryptDetails(View):
    @staticmethod
    def get(request):
        is_superuser = request.user.is_superuser
        if is_superuser:
            try:
                decrypt_details = DecryptInfo.objects.all().order_by('-id')[:10]
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
            info = get_object_or_404(DecryptInfo, id=id)
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
        listing_decrypt_info = get_object_or_404(DecryptInfo, id=id)
        return render(request, 'confirm_delete.html', {'object': listing_decrypt_info})

    @staticmethod
    def post(request, id):
        is_superuser = request.user.is_superuser
        listing_decrypt_info = get_object_or_404(DecryptInfo, id=id)
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
