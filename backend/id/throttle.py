from rest_framework.throttling import AnonRateThrottle


class EmailVerificationThrottle(AnonRateThrottle):
    scope = "email_verification"
