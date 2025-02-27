from django.urls import path
from .views import (
    LoginView,
    RegisterUserView,
    RetrieveUserView,
    DeleteUserView,
    LogoutView,
    TokenRefreshView,
    SocialLoginView,
    ChangePasswordView,
    DeleteSocialUserView,
    DisconnectSocialUserView,
    GetSocialUserView
)

urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='register'), #회원가입
    path('login/', LoginView.as_view(), name='login'), # 로그인
    path('logout/', LogoutView.as_view(), name='logout'), # 로그아웃
    path('user/', RetrieveUserView.as_view(), name='user'), # 회원 조회
    path('user/delete/', DeleteUserView.as_view(), name='delete_user'), # 회원 삭제
    path('token/', TokenRefreshView.as_view(), name='token_obtain_pair'),  # 로그인 (JWT 토큰 발급)
    path('password/', ChangePasswordView.as_view(), name='change_password'),  # 비밀번호 변경
    path('social/login/', SocialLoginView.as_view(), name='social_login'), # 소셜 로그인
    path('social/logout/', DisconnectSocialUserView.as_view(), name='social_logout'), # 소셜 로그아웃
    path('social/user/delete/', DeleteSocialUserView.as_view(), name='delete_social_user'), # 소셜 계정 삭제
    path('social/user/', GetSocialUserView.as_view(), name='social_user'), # 소셜 계정 조회
    ]