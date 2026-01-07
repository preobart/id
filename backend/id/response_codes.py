class ResponseCode:
    AUTH_INVALID_CREDENTIALS = "auth.invalid_credentials"
    AUTH_LOGIN_LOCKOUT = "auth.login_lockout"
    AUTH_LOGGED_OUT = "auth.logged_out"
    
    EMAIL_VERIFICATION_REQUIRED = "email.verification_required"
    EMAIL_ALREADY_EXISTS = "email.already_exists"
    EMAIL_CODE_SENT = "email.code_sent"
    EMAIL_CODE_INVALID = "email.code_invalid"
    EMAIL_VERIFIED = "email.verified"
    EMAIL_SEND_FAILED = "email.send_failed"
    EMAIL_SEND_LIMIT_EXCEEDED = "email.send_limit_exceeded"
    
    PASSWORD_MISMATCH = "password.mismatch"  # noqa: S105
    PASSWORD_WEAK = "password.weak"  # noqa: S105
    PASSWORD_RESET_SUCCESS = "password.reset_success"  # noqa: S105
    
    VALIDATION_REQUIRED = "validation.required"
    VALIDATION_INVALID_FORMAT = "validation.invalid_format"
    VALIDATION_CODE_INVALID_FORMAT = "validation.code_invalid_format"
    
    CAPTCHA_INVALID = "captcha.invalid"
    
    USER_NOT_FOUND = "user.not_found"

