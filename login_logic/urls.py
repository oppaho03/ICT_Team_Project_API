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
    SendAuthEmailFromJavaView,
    ChangePasswordView,
    DeleteSocialAccountView,
    SocialLogoutView,

)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'), #회원가입
    path('login/', LoginView.as_view(), name='login'), # 로그인
    path('logout/', LogoutView.as_view(), name='logout'), # 로그아웃
    path('user/', UserProfileView.as_view(), name='user'), # 회원 조회
    path('user/delete/', DeleteUserView.as_view(), name='delete_user'), # 회원 삭제
    path('token/', RefreshTokenView.as_view(), name='token_obtain_pair'),  # refresh 토큰으로 access token 재발급
    path('social/login/google/', GoogleLoginView.as_view(), name='social_user_google'), # google 소셜 로그인
    path('social/login/kakao/', KakaoLoginView.as_view(), name='social_user_kakao'), # kakao 소셜 로그인
    path('password/', ChangePasswordView.as_view(), name='change_password'),  # 비밀번호 변경
    path('social/logout/', SocialLogoutView.as_view(), name='social_logout'), # 소셜 로그아웃
    path('social/user/delete/', DeleteSocialAccountView.as_view(), name='delete_social_user'), # 소셜 계정 삭제
    path('email/send/', SendAuthEmailFromJavaView.as_view(), name='send_auth_email_java'), # smtp
    ]