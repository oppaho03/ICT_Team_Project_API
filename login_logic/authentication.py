import jwt
import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken

from login_logic.models import SocialAccount

User = get_user_model()

class JWTAuthentication(BaseAuthentication):
    """
    Django REST Framework에서 JWT 인증을 처리하는 클래스
    """
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None  # 인증 정보 없음

        try:
            token_type, token = auth_header.split()
            if token_type.lower() != "bearer":
                raise AuthenticationFailed("Invalid token type")

            payload = jwt.decode(token, settings.SIMPLE_JWT['SIGNING_KEY'], algorithms=["HS256"])
            user = User.objects.get(id=payload["user_id"])

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token expired")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token")
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found")

        return (user, token)


class OAuth2Authentication:
    """
    OAuth 2.0 소셜 로그인 처리 클래스 (Google, Kakao, Naver)
    """
    PROVIDERS = {
        "google": {
            "url": "https://oauth2.googleapis.com/tokeninfo?id_token={}",
            "field": "email"
        },
        "kakao": {
            "url": "https://kapi.kakao.com/v2/user/me",
            "headers": {"Authorization": "Bearer {}"},
            "field": "id"
        },
        "naver": {
            "url": "https://openapi.naver.com/v1/nid/me",
            "headers": {"Authorization": "Bearer {}"},
            "field": "response"
        }
    }

    @staticmethod
    def authenticate(provider, access_token):
        """
        소셜 로그인 사용자 인증
        """
        if provider not in OAuth2Authentication.PROVIDERS:
            raise AuthenticationFailed("지원되지 않는 소셜 로그인 제공자입니다.")

        provider_info = OAuth2Authentication.PROVIDERS[provider]
        url = provider_info["url"].format(access_token)
        headers = provider_info.get("headers", {})

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            raise AuthenticationFailed(f"{provider} 인증 실패")

        user_info = response.json()

        # Google의 경우 이메일, Kakao/Naver의 경우 ID 사용
        social_id = user_info.get(provider_info["field"])
        if provider == "naver":
            social_id = user_info["response"]["id"]

        if not social_id:
            raise AuthenticationFailed("유효한 사용자 정보를 가져올 수 없습니다.")

        user, created = User.objects.get_or_create(
            login_id=social_id, provider=provider,
            defaults={"email": user_info.get("email", f"{provider}_{social_id}@example.com")}
        )

        refresh = RefreshToken.for_user(user)
        return {
            "user": user,
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }


from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import BaseAuthentication
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.exceptions import AuthenticationFailed


class SocialAccountAuthentication(BaseAuthentication):
    """
    ✅ SocialAccount 테이블을 조회하여 로그인된 사용자 인증
    """

    def authenticate(self, request):
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return None  # 인증 헤더가 없으면 인증 진행 X

        try:
            token_type, access_token = auth_header.split()
            if token_type.lower() != "bearer":
                return None  # Bearer 토큰 형식이 아니면 인증 진행 X
        except ValueError:
            return None  # 잘못된 형식의 토큰 처리 X

        # ✅ SocialAccount 테이블에서 access_token 조회
        try:
            social_account = SocialAccount.objects.get(access_token=access_token)
            return (social_account.member_id, None)  # ✅ 유저 정보 반환
        except ObjectDoesNotExist:
            raise AuthenticationFailed("유효하지 않은 토큰입니다.")

        return None
