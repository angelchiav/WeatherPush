from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.utils import timezone
from datetime import timedelta
import uuid



class User(AbstractUser):
    email = models.EmailField(
        'Email Address',
        unique=True
    )

    phone = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        validators=[
            RegexValidator(
                regex=r'^\+?1?\d{9,15}$',
                message="Phone number must be entered in format: '+999999999'. Up to 15 digits allowed."
            )
        ],
        help_text="Optional phone number for SMS notifications"
    )

    is_email_verified = models.BooleanField(
        default=False
    )

    is_phone_verified = models.BooleanField(
        default=False
    )

    preferred_language = models.CharField(
        max_length=10,
        choices=[
            ('en', 'English'),
            ('es', 'Spanish'),
        ],
        default='en'
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    def __str__(self):
            return f"{self.first_name} {self.last_name} - ({self.email})"
        
class EmailVerificationToken(models.Model):
    user = models.ForeignKey(
         User,
         on_delete=models.CASCADE,
         related_name='email_tokens'
    )

    token = models.UUIDField(
         default=uuid.uuid4,
         unique=True,
         editable=False
    )

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=24)
        super().save(*args, **kwargs)

    @property
    def is_expired(self):
         return timezone.now() > self.expires_at
    
    @property
    def is_valid(self):
        return not self.is_expired and not self.is_used
    
    def __str__(self):
        return f"Email verification for {self.user.email}"
    
class PasswordResetToken(models.Model):
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='reset_tokens'
    )

    token = models.UUIDField(
        default=uuid.uuid4, 
        unique=True, 
        editable=False
    )

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=1)
        super().save(*args, **kwargs)

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @property
    def is_valid(self):
        return not self.is_expired and not self.is_used

    def __str__(self):
        return f"Password reset for {self.user.email}"
    
    