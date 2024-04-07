import jwt
from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse
from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from userapp.models import User
from userapp.serializers import userserializer, UserLoginSerializer, EmailSerializer
from django.contrib.auth import authenticate

class UserRegistrationAPIView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = userserializer

class UserLoginAPIView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(username=serializer.validated_data['username'],
                            password=serializer.validated_data['password'])
        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)
        return Response({'detail': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class TokenRefreshAPIView(generics.GenericAPIView):
    def post(self, request):
        refresh_token = request.data.get('refresh')
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                access_token = str(token.access_token)
                return Response({'access': access_token}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({'detail': str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        return Response({'detail': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)
    

class UserRegistrationAPIView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = userserializer

    def perform_create(self, serializer):
        user = serializer.save()
        self.send_verification_email(user)

    def send_verification_email(self, user):
        verification_token = self.generate_verification_token(user)
        verification_link = self.build_verification_link(verification_token)
        subject = 'Verify your email'
        message = f'Hi {user.username}, please click the link to verify your email: {verification_link}'
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

    def generate_verification_token(self, user):
        return jwt.encode({'user_id': user.pk}, settings.SECRET_KEY, algorithm='HS256')

    def build_verification_link(self, token):
        return self.request.build_absolute_uri(reverse('verify-email') + f'?token={token}')

class VerifyEmailAPIView(generics.GenericAPIView):
    def get(self, request):
        token = request.GET.get('token')
        if token:
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                user_id = payload['user_id']
                user = User.objects.get(pk=user_id)
                user.is_active = True
                user.save()
                return Response({'detail': 'Email verified successfully'}, status=status.HTTP_200_OK)
            except jwt.ExpiredSignatureError:
                return Response({'detail': 'Token has expired'}, status=status.HTTP_400_BAD_REQUEST)
            except jwt.InvalidTokenError:
                return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'detail': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordAPIView(generics.GenericAPIView):
    serializer_class = EmailSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
            self.send_password_reset_email(user)
        except User.DoesNotExist:
            pass  # Do nothing if the email does not exist to avoid exposing registered emails
        return Response({'detail': 'If the provided email is registered, a password reset email has been sent.'}, status=status.HTTP_200_OK)

    def send_password_reset_email(self, user):
        reset_token = self.generate_reset_token(user)
        reset_link = self.build_reset_link(reset_token)
        subject = 'Reset your password'
        message = f'Hi {user.username}, please click the link to reset your password: {reset_link}'
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

    def generate_reset_token(self, user):
        return jwt.encode({'user_id': user.pk}, settings.SECRET_KEY, algorithm='HS256')

    def build_reset_link(self, token):
        return self.request.build_absolute_uri(reverse('reset-password') + f'?token={token.decode()}')

class ResetPasswordAPIView(generics.GenericAPIView):
    def post(self, request):
        token = request.GET.get('token')
        if token:
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                user_id = payload['user_id']
                user = User.objects.get(pk=user_id)
                new_password = request.data.get('new_password')
                if new_password:
                    user.set_password(new_password)
                    user.save()
                    return Response({'detail': 'Password reset successfully'}, status=status.HTTP_200_OK)
                return Response({'detail': 'New password is required'}, status=status.HTTP_400_BAD_REQUEST)
            except jwt.ExpiredSignatureError:
                return Response({'detail': 'Token has expired'}, status=status.HTTP_400_BAD_REQUEST)
            except jwt.InvalidTokenError:
                return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({'detail': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'detail': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

