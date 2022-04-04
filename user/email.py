"""
this file Use for email sending
"""
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.core.mail import EmailMessage
from .token import account_activation_token


def email_send(request, subject, template, object):
    """
        Email send function
    """
    current_site = get_current_site(request)
    message = render_to_string(template, {
            'user': object,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(object.pk)),
            'token': account_activation_token.make_token(object),
        })
    to_email = object.email
    email = EmailMessage(
                    subject, message, to=[to_email]
        )
    email.send()
    return True
