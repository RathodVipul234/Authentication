"""
this file handle all admin model view
"""
from django.contrib import admin
from .models import Account

# Register your models here.


class AccountAdmin(admin.ModelAdmin):
    """
    AccountAdmin model view
    """
    list_display = ['user', ]


admin.site.register(Account, AccountAdmin)
