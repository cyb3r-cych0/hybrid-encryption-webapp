from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.forms import ModelForm
from .models import Text, TextFile, File


class FileUploadForm(forms.ModelForm):
    class Meta:
        model = File
        fields = ('case_id', 'case_file')

    case_id = forms.CharField(
        widget=forms.TextInput(attrs={'autocomplete': 'new-password', 'placeholder': 'enter ''case ID'}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['case_id'].label = 'CASE ID'.format(self.fields['case_id'].label)
        self.fields['case_file'].label = 'UPLOAD CASE FILE'.format(self.fields['case_file'].label)


class TextForm(ModelForm):
    class Meta:
        model = Text
        fields = ["case_id", "case_name", "case_data"]

    case_id = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'enter case ID'}))
    case_name = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'enter case name/title'}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['case_id'].label = 'CASE ID'.format(self.fields['case_id'].label)
        self.fields['case_name'].label = 'CASE NAME/TITLE'.format(self.fields['case_name'].label)
        self.fields['case_data'].label = 'CASE INFORMATION'.format(self.fields['case_data'].label)


class TextFileForm(ModelForm):
    class Meta:
        model = TextFile
        fields = ["case_id", "case_name", "case_info", "case_file"]

    case_id = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'enter case ID...'}))
    case_name = forms.CharField(widget=forms.TextInput(attrs={'placeholder': 'enter case name/title...'}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['case_id'].label = 'CASE ID'.format(self.fields['case_id'].label)
        self.fields['case_name'].label = 'CASE NAME/TITLE'.format(self.fields['case_name'].label)
        self.fields['case_info'].label = 'CASE INFORMATION'.format(self.fields['case_info'].label)
        self.fields['case_file'].label = 'UPLOAD CASE FILE'.format(self.fields['case_file'].label)


class RegisterForm(UserCreationForm):
    class Meta:
        model = User
        fields = ["username", "email", "password1", "password2"]

    email = forms.EmailField(
        widget=forms.TextInput(attrs={'autocomplete': 'new-password', 'placeholder': 'example@gmail.com'}))
    username = forms.CharField(
        widget=forms.TextInput(attrs={'autocomplete': 'new-password', 'placeholder': 'John/Alice etc...'}))
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password', 'placeholder': 'strong password...'}))
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password', 'placeholder': 'should match...'}))

    email.widget.input_type = 'email'
    password1.widget.input_type = 'password'
    password2.widget.input_type = 'password'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['email'].label = 'YOUR EMAIL'.format(self.fields['email'].label)
        self.fields['username'].label = 'USER NAME'.format(self.fields['username'].label)
        self.fields['password1'].label = 'CREATE PASSWORD'.format(self.fields['password1'].label)
        self.fields['password2'].label = 'REPEAT PASSWORD'.format(self.fields['password2'].label)
