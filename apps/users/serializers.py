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
    

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )
    remember_me = serializers.BooleanField(default=False)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(
                request=self.context.get('request'),
                username=email,  # Django usa username, pero nosotros sobrescribimos `USERNAME_FIELD = 'email'`
                password=password
            )

            if not user:
                raise serializers.ValidationError({
                    'detail': "Invalid email or password."
                })
            if not user.is_active:
                raise serializers.ValidationError({
                    'detail': "This account is inactive."
                })
            if not user.is_email_verified:
                raise serializers.ValidationError({
                    'detail': "Please verify your email before logging in."
                })

            attrs['user'] = user
            return attrs

        raise serializers.ValidationError({
            'detail': "Must include 'email' and 'password'."
        })

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

    def validate_token(self, value):
        try:
            token_obj = EmailVerificationToken.objects.get(token=value)
        except EmailVerificationToken.DoesNotExist:
            raise serializers.ValidationError("Invalid token")
        
        if not token_obj.is_valid:
            raise serializers.ValidationError("Token expired of used")
        
        self.token_obj = token_obj
        return value
    
    def save(self):
        user = self.token_obj.user
        user.is_email_verified = True
        user.save()
        self.token_obj.is_used = True
        self.token_obj.save()
        return user
    
class PasswordResetSerializer(serializers.ModelSerializer):
    token = serializers.UUIDField()
    new_password = serializers.CharField(
        write_only=True, style={'input_style': 'password'},
        validators=[validate_password]
    )
    confirm_password = serializers.CharField(
        write_only=True, style={'input_style': 'password'}
    )

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({'new_password': 'Passwords do not match'})
        return attrs
    
    def validate_token(self, value):
        try:
            token_obj = PasswordResetToken.objects.get(user=value)
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError("Invalid token")
        
        if not token_obj.is_valid:
            raise serializers.ValidationError("Token expired or used")
        
        self.token_obj = token_obj
        return value
    
    def save(self):
        user = self.token_obj.user
        user.set_password(self.validated_data['new_password'])
        user.save()
        self.token_obj.is_used = True
        self.token_obj.save()
        return user
    
