from django.contrib.auth import get_user_model, authenticate
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
import requests
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from .models import SocialAccount
import random
import string
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.mail import EmailMultiAlternatives
from rest_framework import status
from django.conf import settings
from django.template.loader import render_to_string

User = get_user_model()

# 랜덤 ID 생성 유틸 클래스 (소셜 로그인 전용)
class YourSocialLoginViewBase:
    def generate_unique_login_id(self):
        while True:
            login_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
            if not SocialAccount.objects.filter(login_id=login_id).exists():
                return login_id

# 회원가입
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

        if User.objects.filter(nickname=nickname).exists():
            return Response({"error": "이미 사용 중인 닉네임입니다."}, status=400)

        try:
            user = User.objects.get(email=email)
            if user.is_active:
                return Response({"error": "이미 존재하는 이메일입니다."}, status=400)
            else:
                return Response({"message": "이미 등록된 이메일입니다. 이메일 인증을 먼저 진행해주세요."}, status=200)

        except User.DoesNotExist:
            user = User.objects.create_user(
                email=email,
                password=password,
                name=name,
                nickname=nickname,
                contact=contact,
                gender=gender,
                birth=birth,
                is_active=False
            )
            return Response({"message": "회원가입 성공! 이메일 인증을 완료해주세요."}, status=201)

# 로그인
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        user = authenticate(request, email=email, password=password)
        if user is not None:
            if not user.is_active:
                return Response({"error": "이메일 인증이 완료되지 않았습니다."}, status=403)

            refresh = RefreshToken.for_user(user)
            user.token = str(refresh)
            user.save()
            return Response({
                "access": str(refresh.access_token),
                "refresh": str(refresh),
            })
        return Response({"error": "로그인 실패"}, status=401)

# 로그아웃
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

# 비밀번호 변경
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        current_password = request.data.get("current_password")
        new_password = request.data.get("new_password")

        if not user.check_password(current_password):
            return Response({"error": "현재 비밀번호가 일치하지 않습니다."}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({"message": "비밀번호가 성공적으로 변경되었습니다."}, status=status.HTTP_200_OK)

# 토큰 재발급 (Refresh → Access)
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

# 유저 프로필 조회
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

# 회원 탈퇴
class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        user.delete()
        return Response({"message": "회원 탈퇴 완료!"})

# 소셜 계정 삭제
class DeleteSocialAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        provider = request.data.get("provider")
        user = request.user
        try:
            social_account = SocialAccount.objects.get(member_id=user, provider=provider)
            social_account.delete()
            return Response({"message": f"{provider} 계정 연결이 해제되었습니다."}, status=status.HTTP_200_OK)
        except SocialAccount.DoesNotExist:
            return Response({"error": f"{provider} 계정이 존재하지 않습니다."}, status=status.HTTP_404_NOT_FOUND)

# 소셜 로그아웃
class SocialLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        provider = request.data.get("provider")
        access_token = request.data.get("access_token")

        if provider == "kakao":
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.post("https://kapi.kakao.com/v1/user/logout", headers=headers)
            if response.status_code == 200:
                return Response({"message": "카카오 로그아웃 성공"}, status=status.HTTP_200_OK)
            return Response({"error": "카카오 로그아웃 실패"}, status=response.status_code)

        elif provider == "google":
            return Response({"message": "구글 로그아웃은 클라이언트에서 처리해야 합니다."}, status=status.HTTP_200_OK)

        return Response({"error": "지원하지 않는 provider입니다."}, status=status.HTTP_400_BAD_REQUEST)

# 구글 소셜 로그인
class GoogleLoginView(YourSocialLoginViewBase, APIView):
    permission_classes = [AllowAny]

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
        name = decoded_id_token.get("name") or "GoogleUser"
        provider_id = decoded_id_token.get("sub")

        user, _ = User.objects.get_or_create(
            email=email,
            defaults={
                "name": name,
                "nickname": "go" + self.generate_unique_login_id(),
                "is_active": True,
            }
        )

        if not user.is_active:
            return Response({"message": "이메일 인증이 필요합니다."}, status=403)

        # 토큰에 사용자 정보를 넣기 위해 해당 사용자를 인자로 사용
        refresh = RefreshToken.for_user(user)

        # 소셜 계정 생성 or 연결 (있으면 불러오고 없으면 생성)
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

# 카카오 소셜 로그인
class KakaoLoginView(YourSocialLoginViewBase, APIView):
    permission_classes = [AllowAny]

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

        user, _ = User.objects.get_or_create(
            email=email,
            defaults={
                "name": "KakaoUser",
                "nickname": "ka" + self.generate_unique_login_id(),
                "is_active": True,
            }
        )

        if not user.is_active:
            return Response({"message": "이메일 인증이 필요합니다."}, status=403)

        # 토큰에 사용자 정보를 넣기 위해 해당 사용자를 인자로 사용
        refresh = RefreshToken.for_user(user)

        #  소셜 계정 생성 or 연결 (있으면 불러오고 없으면 생성)
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


# 이메일 인증 코드 전송 (Java 요청 처리)
class SendAuthEmailFromJavaView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        code = request.data.get("code")

        if not email or not code:
            return Response({"error": "이메일과 인증 코드가 모두 필요합니다."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            html_content = render_to_string("email.html", {"code": code})

            email_message = EmailMultiAlternatives(
                subject="[VITA] 이메일 인증 코드",
                body="이메일 인증을 위한 코드입니다.",
                from_email=settings.EMAIL_HOST_USER,
                to=[email],
            )
            email_message.attach_alternative(html_content, "text/html")
            email_message.send()

            return Response({"message": "이메일 전송 성공!"}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": f"이메일 전송 실패: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
