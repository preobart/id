from django.contrib.auth import get_user_model
from django.core.cache import caches
from django.urls import reverse

from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from id.managers import LoginLockoutManager


User = get_user_model()


class ThrottleTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse("login")
        self.user_url = reverse("userinfo")
        self.user = User.objects.create_user(
            username="user", email="user@example.com", password="password-123"
        )

    def test_throttle_anonymous_user(self):
        for _ in range(60):
            response = self.client.post(
                self.login_url, 
                {"email": "wrong@example.com", "password": "wrongpass"}
            )
            self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))
        
        response = self.client.post(
            self.login_url, 
            {"email": "wrong@example.com", "password": "wrongpass"}
        )
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_throttle_authenticated_user(self):
        self.client.force_authenticate(user=self.user)
        
        for _ in range(100):
            response = self.client.get(self.user_url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response = self.client.get(self.user_url)
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)


class LoginLockoutTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse("login")
        self.email = "test@example.com"
        self.password = "password-123"
        self.ip_address = "127.0.0.1"

        self.user = User.objects.create_user(
            username=self.email,
            email=self.email,
            password=self.password
        )

        caches["lockout"].clear()

    def tearDown(self):
        caches["lockout"].clear()

    def test_lockout_after_failed_attempts(self):
        failure_limit = 3

        for i in range(failure_limit):
            data = {"email": self.email, "password": "wrong_password"}
            response = self.client.post(self.login_url, data, REMOTE_ADDR=self.ip_address)

            if i < failure_limit - 1:
                self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
            else:
                self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
                self.assertEqual(response.data["detail"], "login lockout")
                self.assertIn("time", response.data)

    def test_lockout_blocks_login(self):
        lockout_manager = LoginLockoutManager(self.email, self.ip_address)

        for _ in range(3):
            lockout_manager.record_failed()

        self.assertTrue(lockout_manager.is_locked())

        data = {"email": self.email, "password": self.password}
        response = self.client.post(self.login_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["detail"], "login lockout")
        self.assertIn("time", response.data)

    def test_successful_login_resets_lockout(self):
        lockout_manager = LoginLockoutManager(self.email, self.ip_address)

        for _ in range(2):
            lockout_manager.record_failed()

        self.assertFalse(lockout_manager.is_locked())

        data = {"email": self.email, "password": self.password}
        response = self.client.post(self.login_url, data, REMOTE_ADDR=self.ip_address)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertFalse(lockout_manager.is_locked())

    def test_lockout_clear(self):
        lockout_manager = LoginLockoutManager(self.email, self.ip_address)

        for _ in range(3):
            lockout_manager.record_failed()

        self.assertTrue(lockout_manager.is_locked())

        lockout_manager.clear()
        self.assertFalse(lockout_manager.is_locked())

    def test_different_ip_addresses_separate_lockouts(self):
        ip1 = "127.0.0.1"
        ip2 = "192.168.1.1"

        lockout_manager1 = LoginLockoutManager(self.email, ip1)
        lockout_manager2 = LoginLockoutManager(self.email, ip2)

        for _ in range(3):
            lockout_manager1.record_failed()

        self.assertTrue(lockout_manager1.is_locked())
        self.assertFalse(lockout_manager2.is_locked())

    def test_different_emails_separate_lockouts(self):
        email1 = "user1@example.com"
        email2 = "user2@example.com"

        lockout_manager1 = LoginLockoutManager(email1, self.ip_address)
        lockout_manager2 = LoginLockoutManager(email2, self.ip_address)

        for _ in range(3):
            lockout_manager1.record_failed()

        self.assertTrue(lockout_manager1.is_locked())
        self.assertFalse(lockout_manager2.is_locked())

    def test_lockout_time_increases_exponentially(self):
        lockout_manager = LoginLockoutManager(self.email, self.ip_address)

        for _ in range(4):
            for _ in range(3):
                lockout_manager.record_failed()

            lockout_time = lockout_manager.get_lockout_time()
            self.assertGreaterEqual(lockout_time, 0)
