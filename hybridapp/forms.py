from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.utils.safestring import mark_safe
from django.forms import ModelForm
from .models import Text, TextFile, File


class FileForm(forms.ModelForm):
    class Meta:
        model = File
        fields = ('file_id', 'file_name')

    file_id = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'enter ''File ID'}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['file_id'].label = mark_safe('<strong>FILE ID</strong>').format(self.fields['file_id'].label)
        self.fields['file_name'].label = mark_safe('File Upload').format(self.fields['file_name'].label)


class TextForm(ModelForm):
    class Meta:
        model = Text
        fields = ["text_id", "text_name", "text_cipher"]

    text_id = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'enter Text ID'}))
    text_name = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'enter Text Name'}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['text_id'].label = mark_safe('<strong>TEXT ID</strong>').format(self.fields['text_id'].label)
        self.fields['text_name'].label = mark_safe('<strong>TEXT NAME</strong>').format(self.fields['text_name'].label)
        self.fields['text_cipher'].label = mark_safe('<strong>TEXT INFORMATION</strong>').format(self.fields['text_cipher'].label)


class TextFileForm(ModelForm):
    class Meta:
        model = TextFile
        fields = ["textfile_id", "textfile_name", "textfile_text", "textfile_file"]

    textfile_id = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'enter TextFile ID'}))
    textfile_name = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'enter TextFile Name'}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['textfile_id'].label = mark_safe('<strong>TEXTFILE ID</strong>').format(self.fields['textfile_id'].label)
        self.fields['textfile_name'].label = mark_safe('<strong>TEXTFILE NAME</strong>').format(self.fields['textfile_name'].label)
        self.fields['textfile_text'].label = mark_safe('<strong>TEXT INFORMATION</strong>').format(self.fields['textfile_text'].label)
        self.fields['textfile_file'].label = mark_safe('<strong>UPLOAD FILE</strong>').format(self.fields['textfile_file'].label)


class RegisterForm(UserCreationForm):
    class Meta:
        model = User
        fields = ["username", "email", "password1", "password2"]

    email = forms.EmailField(
        widget=forms.TextInput(attrs={'autocomplete': 'new-password', 'placeholder': 'example@gmail.com'}))
    username = forms.CharField(
        widget=forms.TextInput(attrs={'autocomplete': 'new-password', 'placeholder': 'John/Alice'}))
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password', 'placeholder': 'strong password'}))
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password', 'placeholder': 'should match'}))

    email.widget.input_type = 'email'
    password1.widget.input_type = 'password'
    password2.widget.input_type = 'password'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['email'].label = mark_safe('<strong>YOUR EMAIL</strong>').format(self.fields['email'].label)
        self.fields['username'].label = mark_safe('<strong>USER NAME</strong>').format(self.fields['username'].label)
        self.fields['password1'].label = mark_safe('<strong>CREATE PASSWORD</strong>').format(self.fields['password1'].label)
        self.fields['password2'].label = mark_safe('<strong>REPEAT PASSWORD</strong>').format(self.fields['password2'].label)
