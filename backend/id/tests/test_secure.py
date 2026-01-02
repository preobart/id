from django.contrib.auth import get_user_model
from django.urls import reverse

from rest_framework import status
from rest_framework.test import APIClient, APITestCase


User = get_user_model()


class SecureTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse("login")
        self.user_url = reverse("userinfo")
        self.csrf = reverse("csrf")
        self.user = User.objects.create_user(
            username="user", email="user@example.com", password="password-123"
        )

    def test_throttle_anonymous_user(self):
        for _ in range(61):
            response = self.client.post(self.login_url, {"email": "wrong@example.com", "password": "wrongpass"})
            self.assertIn(response.status_code, (status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN, status.HTTP_429_TOO_MANY_REQUESTS))
            if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                self.assertIn("throttled", response.data["detail"])

    def test_throttle_authenticated_user(self):
        self.client.force_authenticate(user=self.user)
        for _ in range(101):
            response = self.client.get(self.user_url)
            self.assertIn(response.status_code, (status.HTTP_200_OK, status.HTTP_429_TOO_MANY_REQUESTS))
            if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                self.assertIn("throttled", response.data["detail"])
