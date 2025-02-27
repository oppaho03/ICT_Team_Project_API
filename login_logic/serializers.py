from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password, check_password
from .models import SocialAccount

# Django에서 현재 설정된 User 모델 가져오기
User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """🔹 전체 User 정보를 직렬화하는 기본 Serializer"""

    class Meta:
        model = User
        fields = '__all__'  # ✅ 모든 필드를 포함


class UserLoginSerializer(serializers.Serializer):
    """🔹 로그인 Serializer - JWT 토큰 반환"""

    email = serializers.EmailField()  # ✅ email을 로그인 ID로 사용
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        # ✅ 직접 사용자 조회 (authenticate() 대신)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("아이디 또는 비밀번호가 올바르지 않습니다.")

        # ✅ 비밀번호 검증 (check_password 사용)
        if not check_password(password, user.password):
            raise serializers.ValidationError("아이디 또는 비밀번호가 올바르지 않습니다.")

        # JWT 토큰 생성
        refresh = RefreshToken.for_user(user)
        # 로그인 시 생성된 Refresh Token을 User 모델에 저장
        user.token = str(refresh)
        user.save()

        return {
            "user_id": user.id,  # 사용자 ID 반환
            "email": user.email,  # 이메일 반환
            "access": str(refresh.access_token),  # 액세스 토큰
            "refresh": str(refresh)  # 리프레시 토큰
        }


class UserRegisterSerializer(serializers.ModelSerializer):
    """🔹 회원가입 Serializer - 비밀번호 해싱 포함"""

    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'name', 'nickname', 'birth', 'gender', 'contact', 'address']

    def create(self, validated_data):  # 회원가입 시 비밀번호를 해싱하여 저장
        validated_data['password'] = make_password(validated_data['password'])  # 비밀번호 해싱 적용
        return super().create(validated_data)


class DeleteUserSerializer(serializers.Serializer): # 회원 삭제
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        if not data["password"]:
            raise serializers.ValidationError("비밀번호를 입력해야 합니다.")
        return data


class TokenRefreshRequestSerializer(serializers.Serializer): # 토큰 재생성
    refresh = serializers.CharField()

    def validate_refresh(self, value):
        if not value:
            raise serializers.ValidationError("Refresh token is required")
        return value




class SocialLoginSerializer(serializers.Serializer):
    provider = serializers.ChoiceField(choices=["google", "naver", "kakao"])
    access_token = serializers.CharField()

    def validate(self, data):
        """✅ access_token이 유효한지 검증"""
        if not data.get("access_token"):
            raise serializers.ValidationError("Access Token이 필요합니다.")
        return data



class SocialAccountSerializer(serializers.ModelSerializer):
    """✅ 소셜 로그인 계정 직렬화"""
    class Meta:
        model = SocialAccount
        fields = ["provider", "provider_id", "login_id", "login_modified_dt"]
