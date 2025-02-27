import uuid

from django.contrib.auth import get_user_model
from django.utils.timezone import now
import requests
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status

from .models import SocialAccount
from .serializers import UserSerializer, UserLoginSerializer, UserRegisterSerializer, SocialAccountSerializer

User = get_user_model()


# 🔹 회원가입 (이메일 인증 없음)
class RegisterUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "회원가입 성공."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# 🔹 로그인 (JWT 토큰 반환)
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# 🔹 JWT 리프레시 토큰을 사용해 Access Token 재발급
class TokenRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get("refresh")

        if not refresh_token:
            return Response({"error": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            refresh = RefreshToken(refresh_token)
            new_access_token = str(refresh.access_token)

            return Response(
                {"access": new_access_token, "refresh": refresh_token},
                status=status.HTTP_200_OK,
            )
        except Exception:
            return Response({"error": "Invalid refresh token"}, status=status.HTTP_400_BAD_REQUEST)


# 🔹 비밀번호 변경
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """✅ 비밀번호 변경 API"""
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        if not user.check_password(old_password):
            return Response({"error": "현재 비밀번호가 올바르지 않습니다."}, status=status.HTTP_400_BAD_REQUEST)
        if len(new_password) < 8:
            return Response({"error": "비밀번호는 최소 8자 이상이어야 합니다."}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({"message": "비밀번호가 변경되었습니다."}, status=status.HTTP_200_OK)


# 🔹 현재 로그인한 사용자 정보 반환
class RetrieveUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


# 🔹 회원 탈퇴
class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        user.delete()
        return Response({"message": "계정이 삭제되었습니다."}, status=status.HTTP_204_NO_CONTENT)


# 로그아웃 (JWT 토큰 블랙리스트 등록)
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """✅ 로그아웃 API (Refresh Token 블랙리스트 등록)"""
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response({"error": "Refresh 토큰이 필요합니다."}, status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response({"message": "로그아웃 성공"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return Response({"error": "토큰이 유효하지 않거나 이미 로그아웃됨"}, status=status.HTTP_400_BAD_REQUEST)


class SocialLoginView(APIView):
    """✅ 소셜 로그인 API (Google, Naver, Kakao)"""
    permission_classes = [AllowAny]

    def post(self, request):
        provider = request.data.get("provider")
        access_token = request.data.get("access_token")

        if provider not in ["google", "naver", "kakao"]:
            return Response({"error": "지원하지 않는 소셜 로그인입니다."}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ 소셜 로그인 사용자 정보 가져오기
        user_info = self.get_social_user_info(provider, access_token)
        if not user_info:
            return Response({"error": "소셜 로그인 실패"}, status=status.HTTP_400_BAD_REQUEST)

        email = user_info.get("email")
        provider_id = user_info.get("id")
        nickname = user_info.get("nickname")

        # ✅ User 테이블이 없어도 JWT 발급 가능하도록 최소한의 정보 저장
        user, _ = User.objects.get_or_create(
            email=email,
            defaults={"nickname": nickname, "password": ""},
        )

        # ✅ 소셜 계정 저장 시 member_id 추가
        random_login_id = self.generate_unique_login_id()
        social_account, created = SocialAccount.objects.get_or_create(
            member_id=user,  # ✅ user와 연결
            provider=provider,
            provider_id=provider_id,
            defaults={
                "login_id": random_login_id,
                "access_token": access_token,
                "status": "active",
            },
        )

        social_account.access_token = access_token
        social_account.login_modified_dt = now()
        social_account.save()

        # ✅ JWT 토큰 발급
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        return Response(
            {
                "access": str(access),
                "refresh": str(refresh),
                "user": {
                    "email": user.email,
                    "nickname": user.nickname,
                    "provider": provider,
                    "provider_id": provider_id,
                    "login_id": social_account.login_id,
                },
            },
            status=status.HTTP_200_OK,
        )

    def generate_unique_login_id(self):
        """✅ 중복되지 않는 랜덤한 login_id 생성"""
        while True:
            random_login_id = str(uuid.uuid4())[:12]  # 12자리 랜덤 문자열 생성
            if not SocialAccount.objects.filter(login_id=random_login_id).exists():
                return random_login_id

    def get_social_user_info(self, provider, access_token):
        """✅ 소셜 로그인 사용자 정보 가져오기"""
        urls = {
            "google": "https://www.googleapis.com/oauth2/v3/userinfo",
            "naver": "https://openapi.naver.com/v1/nid/me",
            "kakao": "https://kapi.kakao.com/v2/user/me",
        }

        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(urls[provider], headers=headers)

        print(f"🔹 {provider} API 요청: {urls[provider]}")
        print(f"🔹 요청 헤더: {headers}")
        print(f"🔹 응답 코드: {response.status_code}")
        print(f"🔹 응답 데이터: {response.json()}")

        if response.status_code != 200:
            return None

        user_info = response.json()
        kakao_account = user_info.get("kakao_account", {})
        properties = user_info.get("properties", {})

        if provider == "google":
            return {"id": user_info.get("sub"), "email": user_info.get("email"), "nickname": user_info.get("name")}
        elif provider == "naver":
            response_data = user_info.get("response", {})
            return {"id": response_data.get("id"), "email": response_data.get("email"),
                    "nickname": response_data.get("nickname")}
        elif provider == "kakao":
            return {
                "id": user_info.get("id"),
                "email": kakao_account.get("email", f"kakao_{user_info['id']}@example.com"),
                "nickname": properties.get("nickname", "No Nickname"),
            }

        return None

        return None

class GetSocialUserView(APIView):
    """✅ 로그인된 사용자의 소셜 계정 정보 조회"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        social_accounts = SocialAccount.objects.filter(member_id=request.user)
        serializer = SocialAccountSerializer(social_accounts, many=True)  # ✅ values() 제거하고 직렬화
        return Response({"social_accounts": serializer.data}, status=status.HTTP_200_OK)


class DisconnectSocialUserView(APIView):
    """✅ 특정 provider의 소셜 계정 연결 해제"""
    permission_classes = [IsAuthenticated]

    def delete(self, request, provider_id):
        deleted_count, _ = SocialAccount.objects.filter(provider_id=provider_id, member_id=request.user).delete()

        if deleted_count == 0:
            return Response({"error": "해당 소셜 계정을 찾을 수 없음"}, status=status.HTTP_404_NOT_FOUND)

        return Response({"message": "소셜 계정 연결 해제 완료"}, status=status.HTTP_200_OK)


class DeleteSocialUserView(APIView):
    """✅ 소셜 로그인 사용자 탈퇴 (계정 삭제)"""
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        user.delete()  # ✅ 사용자의 모든 데이터 삭제
        return Response({"message": "회원 탈퇴 완료"}, status=status.HTTP_200_OK)