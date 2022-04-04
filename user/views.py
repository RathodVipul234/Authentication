"""
user app view.py file
"""
from django.shortcuts import render, redirect
from django.views.generic import CreateView, TemplateView, View
from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout
from django.contrib.messages import constants as messages
from django.contrib import messages
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.hashers import make_password

from user.token import account_activation_token
from user.forms import UserRegistrationForm, PasswordResetEmailForm, \
    SetNewPasswordForm, UpdatePasswordForm
from user.models import Account
from user.email import email_send
# Create your views here.


class UserRegistration(CreateView):
    """
    UserRegistration
    """
    form_class = UserRegistrationForm
    model = User
    template_name = "users/registrations.html"

    def form_valid(self, form):
        """
        form_valid method
        """
        form = form.save()
        Account.objects.create(user=form)
        return redirect('login')


class HomePageView(TemplateView):
    """
    homepage view
    """
    template_name = 'home.html'


class LoginView(TemplateView):
    """
    Login view class
    """
    template_name = "users/login.html"
    model = User

    def get_context_data(self, **kwargs):
        """
        get_context_data function
        """
        context = super().get_context_data(**kwargs)
        return context

    def post(self, request, *args, **kwargs):
        """
        Post method
        """
        user_name = self.request.POST.get('username')
        password = self.request.POST.get('password')
        try:
            user = User.objects.get(email=user_name)
            user_name = user.username
        except User.DoesNotExist:
            pass
        user = authenticate(request, username=user_name, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')
        elif User.objects.filter(username=user_name):
            error = "Please Enter Valid Password"
        else:
            error = "User Not Found."
        return render(request, "users/login.html", {'error': error})


class LogoutView(View):
    """
        Logout view
    """
    def get(self, request):
        """
        het method
        """
        logout(request)
        return redirect('login')


class PasswordResetView(TemplateView):
    """
    PasswordResetView class
    """
    template_name = "password/password_reset.html"
    form_class = PasswordResetEmailForm

    def get_context_data(self, **kwargs):
        """
        get_context_data function
        """
        context = super().get_context_data()
        context['form'] =self.form_class
        return context

    def post(self, *args, **kwargs):
        """
        post method
        """
        form = PasswordResetEmailForm(self.request.POST)
        if form.is_valid():
            email_send(self.request, "Rest Password", "password/password_reset_email.html",
                       form.cleaned_data.user)
            return redirect('password_reset_done')
        return render(self.request, self.template_name, {'form': form})


class SetNewPasswordView(TemplateView):
        """
        SetNewPasswordView class
        """
        template_name = "password/password_reset_confirm.html"
        form_class = SetNewPasswordForm

        def get_context_data(self, **kwargs):
            """
            get_context_data method
            """
            context = super().get_context_data()
            context['form'] = self.form_class
            return context

        def post(self, *args, **kwargs):
            """
            post method
            """
            form = SetNewPasswordForm(self.request.POST)
            uidb64 = kwargs['uidb64']
            token = kwargs['token']
            if form.is_valid():
                try:
                    uid = force_bytes(urlsafe_base64_decode(uidb64))
                    user = User.objects.get(id=uid)
                except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                    user = None

                if user is not None and account_activation_token.check_token(user, token):
                    user.set_password(form.cleaned_data['password1'])
                    user.save()
                    messages.success(self.request, 'Password reset successfully.')
                    return redirect('password_reset_complete')
            return render(self.request, self.template_name, {'form': form})


class ChangePasswordView(TemplateView):
    """
    ChangePasswordView class
    """
    template_name = "password/update_password.html"
    form_class = UpdatePasswordForm

    def get_context_data(self, **kwargs):
        """
        get_context_data method
        """
        context = super().get_context_data()
        context['form'] = self.form_class
        return context

    def post(self, request):
        """
        Post method
        """
        form = UpdatePasswordForm(request.POST, request=request)
        if form.is_valid():
            user = request.user
            user.password = make_password(form.cleaned_data['new_password'])
            user.save()
            messages.success(self.request, 'Password change successfully.')
            return redirect('home')
        return render(self.request, self.template_name, {'form': form})
