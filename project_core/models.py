from django.conf import settings
from django.db import models
from django.contrib.auth.models import User
import hashlib
import os
import binascii


class PreviousPassword(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='previous_passwords')
    password = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    class Meta:
        ordering = ['-created_at']  # Orders by most recent first


class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token_hash = models.CharField(max_length=40)  # SHA-1 produces a 40-char hex string
    created_at = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def save_token(self, plain_token):
        # Hashes the plain token with SHA-1 and saves it.
        # Project requirement: Use SHA-1
        self.token_hash = hashlib.sha1(plain_token.encode('utf-8')).hexdigest()
        self.save()

    @staticmethod
    def generate_token():
        # Generates a random secure token.
        return binascii.hexlify(os.urandom(5)).decode()

    def verify(self, plain_token):
        """Checks if the provided plain token matches the stored hash."""
        input_hash = hashlib.sha1(plain_token.encode('utf-8')).hexdigest()
        return input_hash == self.token_hash
