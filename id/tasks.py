from django.conf import settings
from django.core.mail import send_mail

from celery import shared_task


@shared_task
def send_code_email_task(email, code):
    try:
        send_mail(
            subject="Verification Code",
            message=f"Your verification code is: {code}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        return True
    except Exception:  # noqa: BLE001
        return False
