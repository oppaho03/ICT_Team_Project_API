from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from rest_framework.decorators import api_view
from django.contrib.auth import get_user_model, authenticate
from django.conf import settings
from django.contrib.auth.forms import PasswordResetForm
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
import requests
from decouple import config
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from .models import SocialAccount, EmailVerification
import random
import string

from .utils import send_verification_code, generate_auth_code

User = get_user_model()


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        name = request.data.get("name")
        nickname = request.data.get("nickname")
        contact = request.data.get("contact")
        gender = request.data.get("gender")
        birth = request.data.get("birth")

        try:
            user = User.objects.get(email=email)
            if user.is_active:
                return Response({"error": "이미 존재하는 이메일입니다."}, status=400)
            else:
                # ✅ 이미 비활성화된 유저 → 인증 코드만 다시 전송
                code = generate_auth_code()
                EmailVerification.objects.filter(email=email).delete()
                EmailVerification.objects.create(email=email, code=code)
                send_verification_code(email, code)
                return Response({"message": "이메일 인증 코드가 다시 전송되었습니다."}, status=200)
        except User.DoesNotExist:
            # ✅ 신규 유저 생성
            user = User.objects.create_user(
                email=email, password=password, name=name,
                nickname=nickname, contact=contact, gender=gender, birth=birth, is_active=False
            )

            code = generate_auth_code()
            EmailVerification.objects.create(email=email, code=code)
            send_verification_code(email, code)

            return Response({"message": "회원가입 성공! 이메일로 인증 코드를 보냈습니다."}, status=201)



class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        user = authenticate(request, email=email, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            user.token = str(refresh)  # JWT 토큰 저장
            user.save()
            return Response({
                "access": str(refresh.access_token),
                "refresh": str(refresh),
            })
        return Response({"error": "로그인 실패"}, status=401)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"error": "리프레시 토큰이 필요합니다."}, status=400)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "로그아웃 성공!"})
        except Exception:
            return Response({"error": "유효하지 않은 리프레시 토큰입니다."}, status=400)

class RefreshTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"error": "리프레시 토큰이 필요합니다."}, status=400)

        try:
            token = RefreshToken(refresh_token)
            return Response({"access": str(token.access_token)})
        except Exception:
            return Response({"error": "유효하지 않은 리프레시 토큰입니다."}, status=401)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "email": user.email,
            "name": user.name,
            "nickname": user.nickname,
            "contact": user.contact,
            "gender": user.gender,
            "birth": user.birth,
            "status": user.status,
        })


class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        user.delete()
        return Response({"message": "회원 탈퇴 완료!"})



class YourSocialLoginViewBase:
    def generate_unique_login_id(self):
        while True:
            login_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
            if not SocialAccount.objects.filter(login_id=login_id).exists():
                return login_id



class GoogleLoginView(APIView):
    permission_classes = [AllowAny]

    def generate_unique_login_id(self):
        while True:
            login_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
            if not SocialAccount.objects.filter(login_id=login_id).exists():
                return login_id

    def post(self, request):
        code = request.data.get("code")
        if not code:
            return Response({"error": "인가 코드가 없습니다."}, status=400)

        token_data = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        token_res = requests.post("https://oauth2.googleapis.com/token", data=token_data)
        token_json = token_res.json()
        id_token_str = token_json.get("id_token")
        access_token = token_json.get("access_token")

        if not id_token_str:
            return Response({"error": "ID Token을 가져오지 못했습니다."}, status=400)

        try:
            decoded_id_token = id_token.verify_oauth2_token(
                id_token_str, google_requests.Request(), settings.GOOGLE_CLIENT_ID)
        except Exception:
            return Response({"error": "Invalid ID Token"}, status=400)

        email = decoded_id_token.get("email")
        name = decoded_id_token.get("name")
        provider_id = decoded_id_token.get("sub")

        user, created = User.objects.get_or_create(email=email, defaults={"name": name})

        # ✅ 이메일 인증 여부 확인
        if not user.is_active:
            return Response({"message": "이메일 인증이 필요합니다."}, status=403)

        refresh = RefreshToken.for_user(user)

        random_login_id = self.generate_unique_login_id()
        social_account, created = SocialAccount.objects.get_or_create(
            member_id=user,
            provider="google",
            provider_id=provider_id,
            defaults={
                "login_id": random_login_id,
                "access_token": access_token,
                "status": "active",
            },
        )

        return Response({
            "email": user.email,
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        })


class KakaoLoginView(APIView):
    permission_classes = [AllowAny]

    def generate_unique_login_id(self):
        while True:
            login_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
            if not SocialAccount.objects.filter(login_id=login_id).exists():
                return login_id

    def post(self, request):
        code = request.data.get("code")
        if not code:
            return Response({"error": "인가 코드가 없습니다."}, status=400)

        token_data = {
            "grant_type": "authorization_code",
            "client_id": settings.KAKAO_CLIENT_ID,
            "client_secret": settings.KAKAO_CLIENT_SECRET,
            "redirect_uri": settings.KAKAO_REDIRECT_URI,
            "code": code,
        }
        token_res = requests.post("https://kauth.kakao.com/oauth/token", data=token_data)
        token_json = token_res.json()
        access_token = token_json.get("access_token")

        if not access_token:
            return Response({"error": "Access Token을 가져오지 못했습니다."}, status=400)

        headers = {"Authorization": f"Bearer {access_token}"}
        user_info_res = requests.get("https://kapi.kakao.com/v2/user/me", headers=headers)
        user_info = user_info_res.json()

        kakao_account = user_info.get("kakao_account", {})
        email = kakao_account.get("email")
        provider_id = str(user_info.get("id"))

        if not email:
            return Response({"error": "이메일 정보를 가져올 수 없습니다."}, status=400)

        user, created = User.objects.get_or_create(email=email)

        # ✅ 이메일 인증 여부 확인
        if not user.is_active:
            return Response({"message": "이메일 인증이 필요합니다."}, status=403)

        refresh = RefreshToken.for_user(user)

        random_login_id = self.generate_unique_login_id()
        social_account, created = SocialAccount.objects.get_or_create(
            member_id=user,
            provider="kakao",
            provider_id=provider_id,
            defaults={
                "login_id": random_login_id,
                "access_token": access_token,
                "status": "active",
            },
        )

        return Response({
            "email": user.email,
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        })



class PasswordResetEmailView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "이메일이 없습니다."}, status=400)

        form = PasswordResetForm({'email': email})
        if form.is_valid():
            form.save(
                request=request,
                from_email=config("EMAIL_HOST_USER"),
                email_template_name='email.html',
            )
            return Response({"message": "비밀번호 재설정 이메일을 보냈습니다."})
        return Response({"error": "유효하지 않은 이메일입니다."}, status=400)

class VerifyEmailCodeView(APIView):
    def post(self, request):
        email = request.data.get("email")
        code = request.data.get("code")

        try:
            record = EmailVerification.objects.get(email=email, code=code)
            if record.is_expired():
                return Response({"error": "코드가 만료되었습니다."}, status=400)
        except EmailVerification.DoesNotExist:
            return Response({"error": "잘못된 인증 코드입니다."}, status=400)

        user = User.objects.get(email=email)
        user.is_active = True
        user.save()

        return Response({"message": "이메일 인증 완료! 이제 로그인하세요."})

class VerifySocialEmailCodeView(APIView):
    def post(self, request):
        email = request.data.get('email')
        code = request.data.get('code')

        if not email or not code:
            return Response({"error": "이메일과 코드가 필요합니다."}, status=400)

        try:
            record = EmailVerification.objects.get(email=email, code=code)
            if record.is_expired():
                return Response({"error": "코드가 만료되었습니다."}, status=400)
        except EmailVerification.DoesNotExist:
            return Response({"error": "잘못된 인증 코드입니다."}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "해당 이메일의 사용자를 찾을 수 없습니다."}, status=404)

        user.is_active = True
        user.save()
        return Response({"message": "이메일 인증 완료! 로그인 가능"})