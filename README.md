# ID Service

## About

ID Service is a Django REST API service for user authentication and management. It provides endpoints for user registration, login, email verification, password reset, and feature flags management.

## API Endpoints

### Authentication

#### `POST /auth/register`
Registers a new user account. Requires email verification to be completed before registration.

**Request Body:**
- `email` (string, required): User email address
- `password` (string, required): User password
- `password2` (string, required): Password confirmation
- `first_name` (string, required): User first name
- `last_name` (string, required): User last name

**Response:**
- `201 Created`: User successfully registered and logged in
- `400 Bad Request`: Invalid input data or email not verified

#### `POST /auth/login`
Authenticates a user and creates a session.

**Request Body:**
- `email` (string, required): User email address
- `password` (string, required): User password

**Response:**
- `200 OK`: User successfully logged in
- `400 Bad Request`: Invalid input data
- `401 Unauthorized`: Invalid credentials
- `403 Forbidden`: Account locked due to too many failed login attempts

#### `POST /auth/logout`
Logs out the current user and destroys the session.

**Response:**
- `200 OK`: User successfully logged out

#### `GET /auth/userinfo`
Returns information about the currently authenticated user.

**Response:**
- `200 OK`: Returns user data (id, first_name, last_name, email)
- `401 Unauthorized`: User not authenticated

#### `GET /auth/csrf`
Returns a CSRF token for the current session.

**Response:**
- `200 OK`: Returns CSRF token

### Email Verification

#### `POST /auth/send-code`
Sends a verification code to the specified email address. Supports email verification and password reset code types. May require SmartCaptcha token if the feature flag is enabled.

**Request Body:**
- `email` (string, required): Email address to send code to
- `code_type` (string, required): Type of code - "email_verification" or "password_reset"
- `token` (string, optional): SmartCaptcha token (required if smartcaptcha_enabled flag is active)

**Response:**
- `200 OK`: Code successfully sent
- `400 Bad Request`: Invalid input data or invalid captcha token
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Failed to send email

#### `POST /auth/verify-code`
Verifies a code sent to the user's email address.

**Request Body:**
- `email` (string, required): Email address
- `code` (string, required): 6-digit verification code
- `code_type` (string, required): Type of code - "email_verification" or "password_reset"

**Response:**
- `200 OK`: Code successfully verified
- `400 Bad Request`: Invalid code or input data

### Password Reset

#### `POST /auth/check-email`
Checks if an email address is registered in the system.

**Request Body:**
- `email` (string, required): Email address to check

**Response:**
- `200 OK`: Email exists in the system
- `404 Not Found`: Email not found

#### `POST /auth/password-reset-confirm`
Resets user password. Requires password reset code to be verified first.

**Request Body:**
- `email` (string, required): User email address
- `password` (string, required): New password
- `password2` (string, required): Password confirmation

**Response:**
- `200 OK`: Password successfully reset
- `400 Bad Request`: Invalid input data, passwords don't match, or code not verified

### Feature Flags

#### `GET /feature-flags`
Returns a list of active feature flags that are targeted for frontend or both frontend and backend.

**Response:**
- `200 OK`: Returns object with `flags` array containing active flag names

### Admin

#### `GET /admin`
Django admin interface for managing the application.

#### `GET /schema`
Returns OpenAPI schema (admin only).

#### `GET /docs`
Swagger UI documentation interface (admin only).
