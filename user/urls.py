"""
this file handel all urls of user  app
"""
from django.urls import path
from django.contrib.auth import views as auth_views
from user import views


urlpatterns = [
    path('', views.HomePageView.as_view(), name="home"),
    path('signUp/', views.UserRegistration.as_view(), name="signUp"),
    path('login/', views.LoginView.as_view(), name="login"),
    path('logout/', views.LogoutView.as_view(), name="logout"),

    path('password_reset/', views.PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(
        template_name='password/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.SetNewPasswordView.as_view(),
         name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(
        template_name='password/password_reset_complete.html'), name='password_reset_complete'),
    path('change/password/', views.ChangePasswordView.as_view(), name='update_password'),
]
