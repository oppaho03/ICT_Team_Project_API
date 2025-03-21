from django.urls import path
from .views import (
    LoginView,
    RegisterView,
    UserProfileView,
    DeleteUserView,
    LogoutView,
    RefreshTokenView,
    GoogleLoginView,
    KakaoLoginView,
    PasswordResetEmailView,
    VerifyEmailCodeView,
    VerifySocialEmailCodeView,

)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'), #회원가입
    path('login/', LoginView.as_view(), name='login'), # 로그인
    path('logout/', LogoutView.as_view(), name='logout'), # 로그아웃
    path('user/', UserProfileView.as_view(), name='user'), # 회원 조회
    path('user/delete/', DeleteUserView.as_view(), name='delete_user'), # 회원 삭제
    path('token/', RefreshTokenView.as_view(), name='token_obtain_pair'),  # refresh 토큰으로 access token 재발급
    path('social/login/google/', GoogleLoginView.as_view(), name='social_user'), # google 소셜 로그인
    path('social/login/kakao/', KakaoLoginView.as_view(), name='social_user'), # kakao 소셜 로그인
    # path('password/', ChangePasswordView.as_view(), name='change_password'),  # 비밀번호 변경
    # path('social/login/', SocialLoginView.as_view(), name='social_login'), # 소셜 로그인
    # path('social/logout/', DisconnectSocialUserView.as_view(), name='social_logout'), # 소셜 로그아웃
    # path('social/user/delete/', DeleteSocialUserView.as_view(), name='delete_social_user'), # 소셜 계정 삭제
    path('reset/password/', PasswordResetEmailView.as_view(), name='send_reset_email'), # 비밀번호 재설정 이메일 전송
    path('verify/email/', VerifyEmailCodeView.as_view(), name='verify_email'), # 이메일 로그인 인증 이메일
    path('verify/social/email/', VerifySocialEmailCodeView.as_view(), name='verify_social_email'), # 소셜 로그인 인증 이메일
    ]