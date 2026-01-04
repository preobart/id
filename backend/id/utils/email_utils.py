from django.conf import settings
from django.core.mail import send_mail


def send_code_email(email, code):
    try:
        send_mail(
            subject="Verification Code",
            message=f"Your verification code is: {code}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        return True
    except Exception:
        return False

