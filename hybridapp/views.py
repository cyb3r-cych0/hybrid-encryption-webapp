from django.shortcuts import render, redirect, HttpResponse, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import cache_control
from django.contrib import messages
from django.http import HttpResponse, Http404

from .models import KeyPair, EncryptedFile, Case, EncryptCase
from .forms import CaseForm, FileUploadForm, RegisterForm, EncryptCaseForm

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

import base64
import hashlib
import base64
import csv
import os
import zipfile
import io


# Functions to access path
"""Functions To Handle Frontend Requests"""


# <<<<<<< HEAD
# =======
""" START USER INFO """
@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_users_backend(request):
    users = User.objects.all()
    user = request.user

    context = {
        'users': users,
        'user': user
    }
    return render(request, 'backend/view_users_backend.html', context)


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def user_details_backend(request, id):
    user = request.user
    try:
        user_details = User.objects.get(id=id)
        texts = Case.objects.filter(user=user_details).count()
        files = EncryptedFile.objects.filter(user=user_details).count()
        reports = EncryptCase.objects.filter(user_id=user_details).count()
        total_files = files + texts + reports

        text = Case.objects.filter(user=user_details).order_by('-id')[:1]
        file = EncryptedFile.objects.filter(user=user_details).order_by('-id')[:1]
        report = EncryptCase.objects.filter(user_id=user_details).order_by('-id')[:1]

    except User.DoesNotExist:
        raise Http404('User Details Not Found!')
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
        raise Http404(f'User Details Not Found! {str(e)}')


    context = {
        'user_details': user_details,
        'total_files': total_files,
        'user': user,
        'file': file,
        'text': text,
        'report': report
    }
    return render(request, 'backend/user_details_backend.html', context)


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def user_cases_backend(request, id):
    user = request.user
    try:
        user_details = User.objects.get(id=id)
        text = Case.objects.filter(user=user_details).order_by('-id')
        file = EncryptedFile.objects.filter(user=user_details).order_by('-id')
        report = EncryptCase.objects.filter(user_id=user_details).order_by('-id')
    except User.DoesNotExist:
        raise Http404('User Details Not Found!')
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
        # raise Http404(f'User Details Not Found! {str(e)}')

    context = {
        'user_details': user_details,
        'user': user,
        'file': file,
        'text': text,
        'report': report
    }
    return render(request, 'backend/user_cases_backend.html', context)


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def filter_user_cases(request, id):
    is_superuser = request.user.is_superuser
    # user_details = User.objects.get(id=id)
    user_details = get_object_or_404(User, id=id)
    user = request.user
    try:
        if request.method == 'POST':
            from_date = request.POST.get('from_date')
            to_date = request.POST.get('to_date')

            search_file_result = EncryptedFile.objects.filter(
                user=user_details,
                encryption_date__range=[from_date, to_date]
            )
            search_text_result = Case.objects.filter(
                user=user_details,
                encryption_date__range=[from_date, to_date]
            )
            search_report_result = EncryptCase.objects.filter(
                user_id=user_details,
                encryption_date__range=[from_date, to_date]
            )

            # Extract date values from the filtered querysets
            date_values = [item.encryption_date for item in search_report_result]
            date = date_values[0] if date_values else None

            context = {
                'files': search_file_result,
                'texts': search_text_result,
                'reports': search_report_result,
                'date_values': date_values,
                'date': date,
                'is_superuser': is_superuser,
                'user_details': user_details,
                'user': user
            }
            return render(request, 'backend/filter_user_cases.html', context)
        else:
            messages.error(request, f'Select Calender Date To Filter Searched Cases.')
            context = {
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


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def search_users(request):
    user = request.user
    query = request.GET.get('q')
    try:
        if query:
            # Perform search in both tables
            # case_files = EncryptedFile.objects.filter(case_id__icontains=query)
            # case_texts = Case.objects.filter(caseID__icontains=query)
            # case_reports = EncryptCase.objects.filter(case_id__icontains=query)
            # count = case_files.count() + case_texts.count() + case_reports.count()
            users = User.objects.filter(username__icontains=query)
            count = users.count()
            context = {
                # 'case_files': case_files,
                # 'case_texts': case_texts,
                # 'case_reports': case_reports,
                # 'query': query,
                # 'count': count,
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



>>>>>>> ac2bd1e (cms-v0.3)
""" START ENCRYPT CASES """

@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def encrypt_case(request):
    form = EncryptCaseForm()
    if request.method == 'POST':
        try:
            form = EncryptCaseForm(request.POST, request.FILES)
            if form.is_valid():
                case_id = form.cleaned_data['case_id']
                case_name = form.cleaned_data['case_name']
                case_info = form.cleaned_data['case_info'].encode()
                case_data = form.cleaned_data['case_file'].read()
                user_id = request.user

                # Fetch user's RSA public key
                key_pair = KeyPair.objects.get(user=user_id)
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
                encrypted_text = base64.b64encode(text_enc_session_key + text_cipher_aes.nonce + text_tag + text_ciphertext + text_original_hash).decode('utf-8')

                # Save encrypted case data to the database
                new_case = EncryptCase.objects.create(
                    case_id=case_id,
                    case_name=case_name,
                    case_info=encrypted_text,
                    case_file=form.cleaned_data['case_file'],
                    case_data=encrypted_file,
                    user_id=user_id
                )

                # software feedback
                if new_case:
                    messages.success(request, 'SUCCESS! Case encrypted and saved.')
                else:
                    messages.error(request, 'FAILED! Something Went Wrong. ')
                return redirect('encrypt')

            context = {
                'form': form
            }
            return render(request, 'encrypt/encrypt_case.html', context)

        except Exception as e:
            messages.error(request, f'FAILED! Error encrypting file: {str(e)}.')
            return redirect('encrypt_case')

    context = {
        'form': form
    }
    return render(request, 'encrypt/encrypt_case.html', context)


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def encrypt_case_data(request):
    form = CaseForm()
    if request.method == 'POST':
        form = CaseForm(request.POST, request.FILES)
        if form.is_valid():
            case_id = form.cleaned_data['caseID']
            case_name = form.cleaned_data['caseName']
            data = form.cleaned_data['caseData'].encode()
            user = request.user

            # Fetch user's RSA public key
            key_pair = KeyPair.objects.get(user=user)
            public_key = RSA.import_key(key_pair.public_key)

            # Hash object for verification
            hash_object = SHA256.new()
            hash_object.update(data)
            original_hash = hash_object.digest()

            # Generate AES, pad & encrypted data
            cipher_rsa = PKCS1_OAEP.new(public_key)
            session_key = get_random_bytes(16)
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(data)
            enc_session_key = cipher_rsa.encrypt(session_key)
            encrypted_data = base64.b64encode(enc_session_key + cipher_aes.nonce + tag + ciphertext + original_hash).decode('utf-8')

            # Save encrypted case data to the database
            new_case = Case.objects.create(
                caseID=case_id,
                caseName=case_name,
                caseData=encrypted_data,
                user=user
            )

            # software feedback
            if new_case:
                messages.success(request, 'SUCCESS! Case data encrypted and saved')
            else:
                messages.error(request, 'FAILED! Something Went Wrong')
            return redirect('encrypt')
        else:
            form = CaseForm()
            messages.error(request, 'FAILED! Something Went Wrong')
            context = {
                'form': form
            }
            return render(request, 'encrypt/encrypt_case_data.html', context)
    context = {
        'form': form
    }
    return render(request, 'encrypt/encrypt_case_data.html', context)


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def upload_and_encrypt_file(request):
    form = FileUploadForm()
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            user = request.user
            case_id = form.cleaned_data['case_id']
            data = form.cleaned_data['file'].read()

            # Fetch user's RSA public key
            key_pair = KeyPair.objects.get(user=user)
            public_key = RSA.import_key(key_pair.public_key)

            # Hash object for verification
            hash_object = SHA256.new()
            hash_object.update(data)
            original_hash = hash_object.digest()

            # Encrypt file data
            session_key = get_random_bytes(16)
            cipher_rsa = PKCS1_OAEP.new(public_key)
            enc_session_key = cipher_rsa.encrypt(session_key)
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(data)

            # Store encrypted data in database
            encrypted_data = enc_session_key + cipher_aes.nonce + tag + ciphertext + original_hash
            new_case = EncryptedFile.objects.create(user=user, case_id=case_id, file=form.cleaned_data['file'], encrypted_data=encrypted_data)

            # software feedback
            if new_case:
                messages.success(request, 'SUCCESS! Case file encrypted and saved.')
            else:
                messages.error(request, 'FAILED! Something Went Wrong. ')
            return redirect('encrypt')
    context = {
        'form': form
    }
    return render(request, 'encrypt/upload_file.html', context)

""" END ENCRYPT CASES """



""" START DECRYPT CASES """

def get_file_inreport(request, id):
    # get encrypted data RSA private key for decryption
    encrypted_file = EncryptCase.objects.get(id=id)
    private_key = RSA.import_key(KeyPair.objects.get(user=encrypted_file.user_id).private_key)

    # Extract components from the decrypted data with correct lengths for slicing
    encrypted_file_data = encrypted_file.case_data
    key_len = private_key.size_in_bytes()
    enc_session_key = encrypted_file_data[:key_len]
    nonce = encrypted_file_data[key_len:key_len+16]
    tag = encrypted_file_data[key_len+16:key_len+32]
    ciphertext = encrypted_file_data[key_len+32:-32]
    file_original_hash = encrypted_file_data[-32:]

    # Decrypt file data
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    decrypted_file_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return decrypted_file_data, file_original_hash


def get_text_inreport(request, id):
    # get encrypted data RSA private key for decryption
    encrypted_file = EncryptCase.objects.get(id=id)

    # Fetch user's private key
    key_pair = KeyPair.objects.get(user=encrypted_file.user_id)
    private_ky = RSA.import_key(key_pair.private_key)

    text_cipher_rsa = PKCS1_OAEP.new(private_ky)
    encrypted_text_data = base64.b64decode(encrypted_file.case_info)  # ensure this is decoding correctly

    # Extract components from the decrypted data with correct lengths for slicing
    ky_len = private_ky.size_in_bytes()
    text_enc_session_key = encrypted_text_data[:ky_len]
    text_nonce = encrypted_text_data[ky_len:ky_len+16]
    text_tag = encrypted_text_data[ky_len+16:ky_len+32]
    text_ciphertext = encrypted_text_data[ky_len+32:-32]
    text_original_hash = encrypted_text_data[-32:]

    # Decrypt the AES session key with RSA private key
    text_session_key = text_cipher_rsa.decrypt(text_enc_session_key)

    # Decrypt the ciphertext using AES
    text_cipher_aes = AES.new(text_session_key, AES.MODE_EAX, nonce=text_nonce)
    decrypted_text_data = text_cipher_aes.decrypt_and_verify(text_ciphertext, text_tag)
    return decrypted_text_data, text_original_hash


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def decrypt_case(request, id):
    # Ensure the user requesting decryption is superuser
    is_superuser = request.user.is_superuser
    user = request.user
    if not is_superuser:
        messages.error(request, f'Unauthorized User! {str(user)}')
        return HttpResponse('Unauthorized access.', status=403)

    try:
        encrypted_file = EncryptCase.objects.get(id=id)
        text_data, text_hash = get_text_inreport(request, id)
        file_data, file_hash = get_file_inreport(request, id)

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
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                    if file_data:
                        zip_file.writestr(f'CASE-ID[{encrypted_file.case_id}] <> FILE-NAME-{encrypted_file.case_file}', file_data)
                    if text_data:
                        zip_file.writestr(f'CASE-ID[{encrypted_file.case_id}] <> TEXT-NAME-{encrypted_file.case_name}.txt', text_data)

                # Set the appropriate response headers for a ZIP file
                response = HttpResponse(zip_buffer.getvalue(), content_type='application/zip')
                response['Content-Disposition'] = f'attachment; filename="CASE-ID:{encrypted_file.case_id} <> DECRYPTED-DATA.zip"'
                messages.success(request, 'SUCCESS! Decryption successful, check downloads')

        if error_message:
            messages.error(request, error_message)
            return HttpResponseRedirect(reverse('decrypt'))

        if response:
            return response  # Return the response if decryption was successful

    except EncryptCase.DoesNotExist:
        messages.error(request, 'FAILED! Case not found.')
        # return HttpResponse('Case not found.', status=404)

    except Exception as e:
        messages.error(request, f'FAILED! Error decrypting data: {str(e)}.')
        # return HttpResponse(f'Error decrypting data: {str(e)}', status=500)

    messages.error(request, 'FAILED! No data found for decryption.')
    return HttpResponseRedirect(reverse('decrypt'))


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def decrypt_case_data(request, id):
    # Ensure the user requesting decryption is superuser
    is_superuser = request.user.is_superuser
    if not is_superuser:
        return HttpResponse('Unauthorized access.', status=403)

    try:
        # Fetch the encrypted case data from the database
        case = Case.objects.get(id=id)
        encrypted_data = base64.b64decode(case.caseData)  # ensure this is decoding correctly

        # Fetch user's private key
        key_pair = KeyPair.objects.get(user=case.user_id)
        private_key = RSA.import_key(key_pair.private_key)

        # Decrypt the data with RSA private key
        cipher_rsa = PKCS1_OAEP.new(private_key)

        # Extract components from the decrypted data with correct lengths for slicing
        key_len = private_key.size_in_bytes()
        enc_session_key = encrypted_data[:key_len]
        nonce = encrypted_data[key_len:key_len+16]
        tag = encrypted_data[key_len+16:key_len+32]
        ciphertext = encrypted_data[key_len+32:-32]
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
            messages.error(request, 'FAILED! Integrity check failed. File tampered.')
            return redirect('decrypt')
            # return HttpResponse('Integrity check failed.', status=400)

        # Return the decrypted data
        response = HttpResponse(decrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="CASE-ID:{case.caseID} <> FILE-NAME:{case.caseName}.txt"'
        messages.success(request, 'SUCCESS! File integrity check passed. Decryption successful, check downloads')
        return response

        # context = {
        #     'response': response,
        #     'case': case,
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

    except Case.DoesNotExist:
        messages.error(request, 'FAILED! Case not found.')
        return redirect('decrypt')
        # return HttpResponse('Case not found.', status=404)
    except Exception as e:
        messages.error(request, f'FAILED! Error decrypting data. {str(e)}. Tampered File.')
        return redirect('decrypt')
        # return HttpResponse(f'Error decrypting data: {str(e)}', status=500)


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def decrypt_and_download_file(request, id):
    # Ensure the user requesting decryption is superuser
    is_superuser = request.user.is_superuser
    if not is_superuser:
        return HttpResponse('Unauthorized access.', status=403)
    try:
        # get encrypted data RSA private key for decryption
        encrypted_file = EncryptedFile.objects.get(id=id)
        private_key = RSA.import_key(KeyPair.objects.get(user=encrypted_file.user_id).private_key)

        # Extract components from the decrypted data with correct lengths for slicing
        encrypted_data = encrypted_file.encrypted_data
        key_len = private_key.size_in_bytes()
        enc_session_key = encrypted_data[:key_len]
        nonce = encrypted_data[key_len:key_len+16]
        tag = encrypted_data[key_len+16:key_len+32]
        ciphertext = encrypted_data[key_len+32:-32]
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
            messages.error(request, 'FAILED! Integrity check failed. File tampered.')
            # return HttpResponse('Integrity check failed.', status=400)
            return redirect('decrypt')
        else:
            messages.success(request, f'SUCCESS! Integrity check passed. {encrypted_file.case_id} Decrypted successful, check downloads')
            # return redirect('decrypt')

            # Prepare response to download decrypted file
            response = HttpResponse(decrypted_data, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="CASE-ID:{encrypted_file.case_id} <> FILE-NAME:{encrypted_file.file.name}"'
            return response

        # Redirect to home page after successful download
        return HttpResponseRedirect(reverse('decrypt'))

    except EncryptedFile.DoesNotExist:
        messages.error(request, 'FAILED! File not found.')
        return redirect('decrypt')
        # return HttpResponse('File not found.', status=404)
    except Exception as e:
        messages.error(request, f'FAILED! Error decrypting file: {str(e)}. Tampered File.')
        return redirect('decrypt')
        # return HttpResponse(f'Error decrypting file: {str(e)}', status=500)

    # # Redirect to home page after successful download
    return HttpResponseRedirect(reverse('decrypt'))

""" END DECRYPT CASES """



""" START SEARCH CASE RECORDS """

@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def search_cases(request):
    user = request.user
    query = request.GET.get('q')
    try:
        if query:
            # Perform search in both tables
            case_files = EncryptedFile.objects.filter(case_id__icontains=query)
            case_texts = Case.objects.filter(caseID__icontains=query)
            case_reports = EncryptCase.objects.filter(case_id__icontains=query)
            count = case_files.count() + case_texts.count() + case_reports.count()
            context = {
                'case_files': case_files,
                'case_texts': case_texts,
                'case_reports': case_reports,
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


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def search_cases_encrypt(request):
    user = request.user
    query = request.GET.get('q')
    try:
        if query:
            # Perform search in both tables
            case_files = EncryptedFile.objects.filter(case_id__icontains=query)
            case_texts = Case.objects.filter(caseID__icontains=query)
            case_reports = EncryptCase.objects.filter(case_id__icontains=query)
            count = case_files.count() + case_texts.count() + case_reports.count()
            context = {
                'case_files': case_files,
                'case_texts': case_texts,
                'case_reports': case_reports,
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


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def search_cases_decrypt(request):
    user = request.user
    query = request.GET.get('q')
    try:
        if query:
            # Perform search in both tables
            case_files = EncryptedFile.objects.filter(case_id__icontains=query)
            case_texts = Case.objects.filter(caseID__icontains=query)
            case_reports = EncryptCase.objects.filter(case_id__icontains=query)
            count = case_files.count() + case_texts.count() + case_reports.count()
            context = {
                'case_files': case_files,
                'case_texts': case_texts,
                'case_reports': case_reports,
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


<<<<<<< HEAD


=======
>>>>>>> ac2bd1e (cms-v0.3)
@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def search_text_cases(request):
    user = request.user
    query = request.GET.get('caseID')
    try:
        if query:
            # Perform search in both tables
            cases = Case.objects.filter(caseID__icontains=query)
            count = cases.count()
            context = {
                'cases': cases,
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


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def search_file_cases(request):
    user = request.user
    query = request.GET.get('case_id')
    try:
        if query:
            # Perform search in both tables
            files = EncryptedFile.objects.filter(case_id__icontains=query)
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


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def search_report_cases(request):
    user = request.user
    query = request.GET.get('case_id')
    try:
        if query:
            # Perform search in both tables
            case_reports = EncryptCase.objects.filter(case_id__icontains=query)
            count = case_reports.count()
            context = {
                'case_reports': case_reports,
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



@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def decrypt_success(request):
    return render(request, 'decrypt/decrypt_success.html')


# Encrypt Frontpage (backend)
@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def encrypt(request):
    try:
        user = request.user
        texts = Case.objects.filter(user=user).count()
        files = EncryptedFile.objects.filter(user=user).count()
        reports = EncryptCase.objects.filter(user_id=user).count()

        total_files = files + texts + reports

        text = Case.objects.filter(user=user).order_by('-id')[:1]
        file = EncryptedFile.objects.filter(user=user).order_by('-id')[:1]
        report = EncryptCase.objects.filter(user_id=user).order_by('-id')[:1]

        context = {
            'user': user,
            'file': file,
            'text': text,
            'report': report,
            'total_files': total_files
        }
        return render(request, 'backend/encrypt.html', context)
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
        return redirect('encrypt')


# View Encrypted text Files (backend)
@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_file(request, id):
    user = request.user
    try:
        file = Case.objects.get(id=id)
    except Case.DoesNotExist:
        raise Http404('File Details Not Found!')
    context = {
        'file': file,
        'user': user
    }
    return render(request, 'encrypt/view_file.html', context)


# view encrypted text and files
@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_files(request):
    user = request.user
    texts = Case.objects.filter(user=user).order_by('-id')[:10]
    files = EncryptedFile.objects.filter(user=user).order_by('-id')[:10]
    reports = EncryptCase.objects.filter(user_id=user).order_by('-id')[:10]

    context = {
        'files': files,
        'texts': texts,
        'reports': reports
    }
    return render(request, 'encrypt/view_files.html', context)



@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_file_backend(request, id):
    user = request.user
    try:
        file = Case.objects.get(id=id)
    except Case.DoesNotExist:
        raise Http404('File Details Not Found!')
    context = {
        'file': file,
        'user': user
    }
    return render(request, 'backend/view_file_backend.html', context)


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_file_decrypt(request, id):
    user = request.user
    try:
        file = Case.objects.get(id=id)
    except Case.DoesNotExist:
        raise Http404('File Details Not Found!')
    context = {
        'file': file,
        'user': user
    }
    return render(request, 'decrypt/view_file_decrypt.html', context)


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_report_backend(request, id):
    user = request.user
    try:
        report = EncryptCase.objects.get(id=id)
    except EncryptCase.DoesNotExist:
        raise Http404('File Details Not Found!')
    context = {
        'report': report,
        'user': user
    }
    return render(request, 'backend/view_report_backend.html', context)


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_report_decrypt(request, id):
    user = request.user
    try:
        report = EncryptCase.objects.get(id=id)
    except EncryptCase.DoesNotExist:
        raise Http404('File Details Not Found!')
    context = {
        'report': report,
        'user': user
    }
    return render(request, 'decrypt/view_report_decrypt.html', context)


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_report_encrypt(request, id):
    user = request.user
    try:
        report = EncryptCase.objects.get(id=id)
    except EncryptCase.DoesNotExist:
        raise Http404('File Details Not Found!')
    context = {
        'report': report,
        'user': user
    }
    return render(request, 'encrypt/view_report_encrypt.html', context)



# View Encrypted Data Files (backend)
@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_data(request, id):
    try:
        file = EncryptedFile.objects.get(id=id)
    except EncryptedFile.DoesNotExist:
        raise Http404('File Details Not Found!')
    context = {
        'file': file
    }
    return render(request, 'encrypt/view_data.html', context)


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_data_backend(request, id):
    user = request.user
    try:
        file = EncryptedFile.objects.get(id=id)
    except EncryptedFile.DoesNotExist:
        raise Http404('File Details Not Found!')
    context = {
        'file': file,
        'user': user
    }
    return render(request, 'backend/view_data_backend.html', context)



@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_data_decrypt(request, id):
    user = request.user
    try:
        file = EncryptedFile.objects.get(id=id)
    except EncryptedFile.DoesNotExist:
        raise Http404('File Details Not Found!')
    context = {
        'file': file,
        'user': user
    }
    return render(request, 'decrypt/view_data_decrypt.html', context)



# Print Encrypted Data Page
@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def print_enc_data(request):
    enc_data = Case.objects.all().order_by('-id')[:1]
    context = {
        'enc_data': enc_data
    }
    return render(request, 'encrypt/view_file.html', context)


# Generate Encryption Keys
def generate_keys(request):
    # Generate RSA key pair
    key = RSA.generate(2048)
    # Extract public and private keys
    public_key = key.publickey().export_key().decode('utf-8')
    private_key = key.export_key().decode('utf-8')
    # Save the keys to the database
    key_pair = KeyPair.objects.create(public_key=public_key, private_key=private_key, user=request.user)
    if key_pair:
        messages.success(request, 'SUCCESS! Keys Generated Successfully')
    else:
        messages.error(request, 'FAILED! Something Went Wrong {Keys}')
    return redirect('encrypt')



# Register New User
def register_user(request):
    form = RegisterForm()
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'SUCCESS! User Registered Successfully.')
            return redirect('login')
        else:
            form = RegisterForm()
            messages.error(request, 'FAILED! Something Went Wrong.')
            context = {
                'form': form
            }
            return render(request, 'registration/register_user.html', context)
    context = {
        'form': form
    }
    return render(request, 'registration/register_user.html', context)



# Decrypt front page (backend)
@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def decrypt(request):
    is_superuser = request.user.is_superuser

    text = Case.objects.all().order_by('-id')[:1]
    file = EncryptedFile.objects.all().order_by('-id')[:1]
    report = EncryptCase.objects.all().order_by('-id')[:1]

    texts = Case.objects.all().count()
    files = EncryptedFile.objects.all().count()
    reports = EncryptCase.objects.all().count()
    case_files = files + texts + reports

    context = {
        'is_superuser': is_superuser,
        'case_files': case_files,
        'text': text,
        'file': file,
        'report': report
    }
    return render(request, 'backend/decrypt.html', context)


# View all encrypted files front decryption side with superuser (backend)
@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_all(request):
    is_superuser = request.user.is_superuser
    user = request.user
    try:
        if is_superuser:
            texts = Case.objects.all().order_by('-id')[:10]
            files = EncryptedFile.objects.all().order_by('-id')[:10]
            reports = EncryptCase.objects.all().order_by('-id')[:10]
        else:
            messages.error(request, f'Error: Unauthorized User {user}')
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
        return redirect('view_all')

    context = {
        'texts': texts,
        'files': files,
        'reports': reports
    }
    return render(request, 'decrypt/view_all.html', context)


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_all_backend(request):
    # is_superuser = request.user.is_superuser
    # if is_superuser:
    user = request.user
    files = Case.objects.all().order_by('-id')[:10]
    f_files = EncryptedFile.objects.all().order_by('-id')[:10]
    reports = EncryptCase.objects.all().order_by('-id')[:10]

    if files or f_files:
        context = {
            'files': files,
            'f_files': f_files,
            'reports': reports,
            'user': user
        }
        return render(request, 'backend/view_all_backend.html', context)
    else:
        messages.error(request, f'No Files Found!')
    return render(request, 'backend/view_all_backend.html')


# Frontend
def frontend(request):
    return render(request, 'frontend.html')


"""Functions To Handle Backend Requests"""


# Backend
@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def backend(request):
    return render(request, 'backend.html')



# update file data (backend)
@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def update(request, id):
    is_superuser = request.user.is_superuser
    if is_superuser:
        listing = Case.objects.get(id=id)
        form = CaseForm(instance=listing)
        if request.method == 'POST':
            form = CaseForm(request.POST, instance=listing)
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


""" START DELETE CASE RECORDS """

@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def delete_case_file(request, id):
    try:
        is_superuser = request.user.is_superuser
        if is_superuser:
            listing_file = EncryptedFile.objects.get(id=id)
            listing_file.delete()
            messages.success(request, 'SUCCESS! File Deleted Successfully')
            return redirect('decrypt')

        elif not is_superuser:
            user = request.user
            messages.error(request, f'FAILED! Unauthorized User: {user}')
            return redirect('encrypt')
        else:
            messages.error(request, 'FAILED! Something Went Wrong')
            return redirect('decrypt')
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
        return redirect('decrypt')


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def delete_case_text(request, id):
    is_superuser = request.user.is_superuser
    try:
        if is_superuser:
            listing_case = Case.objects.get(id=id)
            listing_case.delete()
            messages.success(request, 'SUCCESS! File Deleted Successfully')
            return redirect('decrypt')
        elif not is_superuser:
            user = request.user
            messages.error(request, f'FAILED! Unauthorized User: {user}')
            return redirect('encrypt')
        else:
            messages.error(request, 'FAILED! Something Went Wrong')
            return redirect('decrypt')
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
        return redirect('decrypt')


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def delete_case_report(request, id):
    is_superuser = request.user.is_superuser
    try:
        if is_superuser:
            listing_case_report = EncryptCase.objects.get(id=id)
            listing_case_report.delete()
            messages.success(request, 'SUCCESS! File Deleted Successfully')
            return redirect('decrypt')
        elif not is_superuser:
            user = request.user
            messages.error(request, f'FAILED! Unauthorized User: {user}')
            return redirect('encrypt')
        else:
            messages.error(request, 'FAILED! Something Went Wrong')
            return redirect('decrypt')
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
        return redirect('decrypt')

""" END DELETE CASE RECORDS """


""" START CSV DOWNLOADS"""

@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def export_cases_csv(request):
    try:
        cases = Case.objects.all()
        response = HttpResponse()
        response['Content-Disposition'] = 'attachment; filename=case-texts_export.csv'
        writer = csv.writer(response)
        writer.writerow(['CASE-ID', 'CASE-DATA', 'USER-ID', 'CASE-NAME'])
        case_fields = cases.values_list('caseID', 'caseData', 'user_id', 'caseName')
        for case in case_fields:
            writer.writerow(case)
        return response
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
        return redirect('search_text_cases')


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def export_files_csv(request):
    try:
        files = EncryptedFile.objects.all()
        response = HttpResponse()
        response['Content-Disposition'] = 'attachment; filename=case-files_export.csv'
        writer = csv.writer(response)
        writer.writerow(['CASE-ID', 'CASE-FILE', 'CASE-DATA', 'USER-ID'])
        file_fields = files.values_list('case_id', 'file', 'encrypted_data', 'user_id')
        for file in file_fields:
            writer.writerow(file)
        return response
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
        return redirect('search_file_cases')


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def export_report_csv(request):
    try:
        reports = EncryptCase.objects.all()
        response = HttpResponse()
        response['Content-Disposition'] = 'attachment; filename=case-reports_export.csv'
        writer = csv.writer(response)
        writer.writerow(['CASE-ID', 'CASE-NAME', 'CASE-INFO', 'CASE-FILE', 'CASE-DATA', 'USER-ID'])
        report_fields = reports.values_list('case_id', 'case_name', 'case_info', 'case_file', 'case_data', 'user_id')
        for report in report_fields:
            writer.writerow(report)
        return response
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
        return redirect('search_report_cases')

""" END CSV DOWNLOADS"""


""" START FILTER CASES"""

@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def filter_reports(request):
    is_superuser = request.user.is_superuser
    try:
        if request.method == 'POST':
            from_date = request.POST.get('from_date')
            to_date = request.POST.get('to_date')
            search_result = EncryptCase.objects.raw(
                'select id, case_id, case_name, case_info, case_file, case_data from hybridapp_encryptcase where encryption_date between "' + from_date + '" and "' + to_date + '"')

            # Extract date values from the raw_queryset
            date_values = [item.encryption_date for item in search_result]
            for date_value in date_values:
                date = date_value
            context = {
                'reports': search_result,
                'date_values': date_values,
                'date': date,
                'is_superuser': is_superuser
            }
            return render(request, 'decrypt/filter_reports.html', context)
        else:
            # reports = EncryptCase.objects.all().order_by('-id')[:3]
            messages.error(request, f'Select Calender Date To Filter Searched Reports.')
            context = {
                # 'reports': reports,
                'is_superuser': is_superuser
            }
            return render(request, 'decrypt/filter_reports.html', context)
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
        return redirect('filter_reports')


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def filter_texts(request):
    is_superuser = request.user.is_superuser
    try:
        if request.method == 'POST':
            from_date = request.POST.get('from_date')
            to_date = request.POST.get('to_date')
            search_result = Case.objects.raw(
                'select id, caseID, caseName, caseData from hybridapp_case where encryption_date between "' + from_date + '" and "' + to_date + '"')

            # Extract date values from the raw_queryset
            date_values = [item.encryption_date for item in search_result]
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
            # texts = Case.objects.all().order_by('-id')[:3]
            messages.error(request, f'Select Calender Date To Filter Searched Texts.')
            context = {
                # 'texts': texts,
                'is_superuser': is_superuser
            }
            return render(request, 'decrypt/filter_texts.html', context)
    except Exception as e:
        messages.error(request, f'Error:. {str(e)}')
        return redirect('filter_texts')


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def filter_files(request):
    is_superuser = request.user.is_superuser
    try:
        if request.method == 'POST':
            from_date = request.POST.get('from_date')
            to_date = request.POST.get('to_date')
            search_result = EncryptedFile.objects.raw(
                'select id, case_id, file, encrypted_data from hybridapp_encryptedfile where encryption_date between "' + from_date + '" and "' + to_date + '"')

            # Extract date values from the raw_queryset
            date_values = [item.encryption_date for item in search_result]
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
            # files = EncryptedFile.objects.all().order_by('-id')[:3]
            messages.error(request, f'Select Calender Date To Filter Searched Files.')
            context = {
                # 'files': files,
                'is_superuser': is_superuser
            }
            return render(request, 'decrypt/filter_files.html', context)
    except Exception as e:
        messages.error(request, f'Error: {str(e)}!')
        return redirect('filter_files')


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def filter_cases(request):
    is_superuser = request.user.is_superuser
    try:
        if request.method == 'POST':
            from_date = request.POST.get('from_date')
            to_date = request.POST.get('to_date')

            search_file_result = EncryptedFile.objects.raw(
                'select id, case_id, file, encrypted_data from hybridapp_encryptedfile where encryption_date between "' + from_date + '" and "' + to_date + '"')
            search_text_result = Case.objects.raw(
                'select id, caseID, caseName, caseData from hybridapp_case where encryption_date between "' + from_date + '" and "' + to_date + '"')
            search_report_result = EncryptCase.objects.raw(
                'select id, case_id, case_name, case_info, case_file, case_data from hybridapp_encryptcase where encryption_date between "' + from_date + '" and "' + to_date + '"')

            # Extract date values from the raw_queryset
            date_values = [item.encryption_date for item in search_report_result]
            for date_value in date_values:
                date = date_value
            context = {
                'files': search_file_result,
                'texts': search_text_result,
                'reports': search_report_result,
                'date_values': date_values,
                'date': date,
                'is_superuser': is_superuser
            }
            return render(request, 'backend/filter_cases.html', context)
        else:
            # files = EncryptedFile.objects.all().order_by('-id')[:3]
            messages.error(request, f'Select Calender Date To Filter Searched Cases.')
            context = {
                # 'files': files,
                'is_superuser': is_superuser
            }
            return render(request, 'backend/filter_cases.html', context)
    except Exception as e:
        messages.error(request, f'Error: {str(e)}!')
        return redirect('filter_cases')


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def filter_cases_encrypt(request):
    is_superuser = request.user.is_superuser
    try:
        if request.method == 'POST':
            from_date = request.POST.get('from_date')
            to_date = request.POST.get('to_date')

            search_file_result = EncryptedFile.objects.raw(
                'select id, case_id, file, encrypted_data from hybridapp_encryptedfile where encryption_date between "' + from_date + '" and "' + to_date + '"')
            search_text_result = Case.objects.raw(
                'select id, caseID, caseName, caseData from hybridapp_case where encryption_date between "' + from_date + '" and "' + to_date + '"')
            search_report_result = EncryptCase.objects.raw(
                'select id, case_id, case_name, case_info, case_file, case_data from hybridapp_encryptcase where encryption_date between "' + from_date + '" and "' + to_date + '"')

            # Extract date values from the raw_queryset
            date_values = [item.encryption_date for item in search_report_result]
            for date_value in date_values:
                date = date_value
            context = {
                'files': search_file_result,
                'texts': search_text_result,
                'reports': search_report_result,
                'date_values': date_values,
                'date': date,
                'is_superuser': is_superuser
            }
            return render(request, 'encrypt/filter_cases_encrypt.html', context)
        else:
            # files = EncryptedFile.objects.all().order_by('-id')[:3]
            messages.error(request, f'Select Calender Date To Filter Searched Cases.')
            context = {
                # 'files': files,
                'is_superuser': is_superuser
            }
            return render(request, 'encrypt/filter_cases_encrypt.html', context)
    except Exception as e:
        messages.error(request, f'Error: {str(e)}!')
        return redirect('filter_cases_encrypt')


@login_required(login_url='login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def filter_cases_decrypt(request):
    is_superuser = request.user.is_superuser
    try:
        if request.method == 'POST':
            from_date = request.POST.get('from_date')
            to_date = request.POST.get('to_date')

            search_file_result = EncryptedFile.objects.raw(
                'select id, case_id, file, encrypted_data from hybridapp_encryptedfile where encryption_date between "' + from_date + '" and "' + to_date + '"')
            search_text_result = Case.objects.raw(
                'select id, caseID, caseName, caseData from hybridapp_case where encryption_date between "' + from_date + '" and "' + to_date + '"')
            search_report_result = EncryptCase.objects.raw(
                'select id, case_id, case_name, case_info, case_file, case_data from hybridapp_encryptcase where encryption_date between "' + from_date + '" and "' + to_date + '"')

            # Extract date values from the raw_queryset
            date_values = [item.encryption_date for item in search_report_result]
            for date_value in date_values:
                date = date_value
            context = {
                'files': search_file_result,
                'texts': search_text_result,
                'reports': search_report_result,
                'date_values': date_values,
                'date': date,
                'is_superuser': is_superuser
            }
            return render(request, 'decrypt/filter_cases_decrypt.html', context)
        else:
            # files = EncryptedFile.objects.all().order_by('-id')[:3]
            messages.error(request, f'Select Calender Date To Filter Searched Cases.')
            context = {
                # 'files': files,
                'is_superuser': is_superuser
            }
            return render(request, 'decrypt/filter_cases_decrypt.html', context)
    except Exception as e:
        messages.error(request, f'Error: {str(e)}!')
        return redirect('filter_cases_decrypt')

""" END FILTER CASES """
