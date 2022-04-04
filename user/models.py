"""
Models.py file
"""
from django.db import models
from django.contrib.auth.models import User


# Create your models here.


class Account(models.Model):
    """
    Account Model
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE)
