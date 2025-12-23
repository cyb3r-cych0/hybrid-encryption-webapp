from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.forms import ModelForm
from .models import Text, TextFile, File


class FileForm(forms.ModelForm):
    class Meta:
        model = File
        fields = ('file_id', 'file_name')

    file_id = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'enter ''File ID'}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['file_id'].label = 'FILE ID'.format(self.fields['file_id'].label)
        self.fields['file_name'].label = 'UPLOAD FILE'.format(self.fields['file_name'].label)


class TextForm(ModelForm):
    class Meta:
        model = Text
        fields = ["text_id", "text_name", "text_cipher"]

    text_id = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'enter Text ID'}))
    text_name = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'enter Text Name'}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['text_id'].label = 'TEXT ID'.format(self.fields['text_id'].label)
        self.fields['text_name'].label = 'TEXT NAME'.format(self.fields['text_name'].label)
        self.fields['text_cipher'].label = 'TEXT INFO'.format(self.fields['text_cipher'].label)


class TextFileForm(ModelForm):
    class Meta:
        model = TextFile
        fields = ["textfile_id", "textfile_name", "textfile_text", "textfile_file"]

    textfile_id = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'enter TextFile ID'}))
    textfile_name = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'enter TextFile Name'}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['textfile_id'].label = 'TEXTFILE ID'.format(self.fields['textfile_id'].label)
        self.fields['textfile_name'].label = 'TEXTFILE NAME'.format(self.fields['textfile_name'].label)
        self.fields['textfile_text'].label = 'TEXT INFO'.format(self.fields['textfile_text'].label)
        self.fields['textfile_file'].label = 'UPLOAD FILE'.format(self.fields['textfile_file'].label)


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
        self.fields['email'].label = 'YOUR EMAIL'.format(self.fields['email'].label)
        self.fields['username'].label = 'USER NAME'.format(self.fields['username'].label)
        self.fields['password1'].label = 'CREATE PASSWORD'.format(self.fields['password1'].label)
        self.fields['password2'].label = 'REPEAT PASSWORD'.format(self.fields['password2'].label)
