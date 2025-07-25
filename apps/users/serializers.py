from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from .models import User, EmailVerificationToken, PasswordResetToken

class UserRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )

    password = serializers.CharField(
        write_only=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )

    password2 = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )

    accept_terms = serializers.BooleanField(write_only=True)
    accept_privacy = serializers.BooleanField(write_only=True)

    class Meta:
        model = User
        fields = [
            'email', 'password', 'password2',
            'first_name', 'last_name', 'phone',
            'preferred_language', 'accept_terms', 'accept_privacy'
        ]

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({'password': 'Passwords do not match'})
        if not attrs.get('accept_terms'):
            raise serializers.ValidationError({'accept_terms': 'Terms must be accepted'})
        if not attrs.get('accept_privacy'):
            raise serializers.ValidationError({'accept_privacy': 'Privacy policy must be accepted'})
        
        attrs.pop('password2')
        attrs.pop('accept_terms')
        attrs.pop('accept_privacy')

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

class UserProfileSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'phone', 'preferred_language', 'is_email_verified',
            'is_phone_verified', 'date_joined', 'last_login'
        ]
        read_only_fields = ['email', 'is_email_verified', 'is_phone_verified', 'date_joined', 'last_login']

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip()

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'phone', 'preferred_language']
    
    def validate_phone(self, value):
        if value and self.instance.phone != value:
            self.instance.is_phone_verified = False
        return value
    
    def update(self, instance, validated_data):
        phone = validated_data.get('phone')
        if phone and instance.phone != phone:
            instance.is_phone_verified = False
        return super().update(instance, validated_data)
    
class EmailVerificationTokenSerializer(serializers.ModelSerializer):
    token = serializers.UUIDField()

    