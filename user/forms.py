"""
this file Use for all form handling
"""
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import PasswordResetForm
from django.forms import ValidationError
from django.contrib.auth.password_validation import validate_password
from user.models import Account


class UserRegistrationForm(UserCreationForm):
    """
    UserRegistrationForm
    """
    class Meta:
        """
        meta class
        """
        model = User
        fields = ("username", "first_name", "last_name", "email", "password1", "password2")

    def __init__(self, *args, **kwargs):
        """
        init function
        """
        super().__init__(*args, **kwargs)

        self.fields['username'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Username'
        })

        self.fields['first_name'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'First name'
        })

        self.fields['last_name'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Last name'
        })

        self.fields['email'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Email'
        })

        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Password'
        })

        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Confirm password'
        })


class PasswordResetEmailForm(PasswordResetForm):
    """
    PasswordResetEmailForm form
    """
    fields = ('email', )

    def __init__(self, *args, **kwargs):
        """
        init method
        """
        super().__init__(*args, **kwargs)
        self.fields['email'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'email'
        })

    def clean(self):
        """
        clean method
        """
        cleaned_data = self.cleaned_data
        user = Account.objects.filter(user__email=cleaned_data.get('email')).first()
        if not user:
            raise ValidationError("User not Found")
        return user


class SetNewPasswordForm(forms.Form):
    """
    SetNewPasswordForm
    """
    password1 = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password',
                                          'class': 'form-control', 'placeholder': 'Password'}),
    )
    password2 = forms.CharField(
        label="New password confirmation",
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password',
                                          'class': 'form-control',
                                          'placeholder': 'confirm password'}),
        validators=[validate_password]
    )

    def clean(self):
        """
        clean method
        """
        cleaned_data = super().clean()
        password = cleaned_data.get('password1')
        confirm_password = cleaned_data.get('password2')

        if password != confirm_password:
            raise ValidationError("Password and confirm password does not match.")
        return cleaned_data


class UpdatePasswordForm(forms.Form):
    """
    UpdatePasswordForm
    """
    old_password = forms.CharField(required=True)
    new_password = forms.CharField(required=True, validators=[validate_password])
    confirm_new_password = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        """
        init method
        """
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)
        self.fields['old_password'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'old password'
        })
        self.fields['new_password'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'new password'
        })
        self.fields['confirm_new_password'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'confirm new password'
        })

    def clean(self):
        """
        clean method
        """
        data = super().clean()
        old_password = data.get("old_password")
        new_password = data.get("new_password")
        confirm_new_password = data.get("confirm_new_password")
        is_valid = self.request.user.check_password(old_password)

        if new_password is None:
            raise ValidationError("Please enter valid password")

        if new_password != confirm_new_password:
            raise ValidationError("New password and Confirm new password does not match.")
        elif not is_valid:
            raise ValidationError("Please enter correct old password")
        return data
