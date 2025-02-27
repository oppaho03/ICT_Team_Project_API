from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models

# 성별 선택지
GENDER_CHOICES = [
    ('male', 'Male'),
    ('female', 'Female'),
    ('screct', 'Screct'),
]

# 계정 상태 선택지
STATUS_CHOICES = [
    ('active', 'Active'),
    ('inactive', 'Inactive'),
    ('banned', 'Banned'),
]

# 소셜 로그인 제공자 선택지
PROVIDER_CHOICES = [
    ('google', 'Google'),
    ('kakao', 'Kakao'),
    ('naver', 'Naver'),
]

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("이메일을 입력해야 합니다.")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)  # 비밀번호 해싱
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("role", "admin")
        user = self.create_user(email, password, **extra_fields)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user




class User(AbstractBaseUser):
    email = models.EmailField(unique=True, verbose_name="이메일", max_length=30)
    password = models.CharField(max_length=128, verbose_name="비밀번호")  # Django가 비밀번호 해싱
    role = models.CharField(max_length=30, verbose_name="역할", default="user")
    name = models.CharField(max_length=50, verbose_name="이름")
    nickname = models.CharField(max_length=50, unique=True, null=True, blank=True, verbose_name="닉네임")
    birth = models.DateField(null=True, blank=True, verbose_name="생년월일")
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, null=True, blank=True, verbose_name="성별")
    contact = models.CharField(max_length=15, verbose_name="연락처")
    address = models.TextField(null=True, blank=True, verbose_name="주소")
    token = models.TextField(max_length=255, null=True, blank=True, verbose_name="인증 토큰(refresh)")  # JWT 토큰 저장 가능
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="가입일")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="업데이트일") # 없으면 가입일
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active', verbose_name="상태")

    # ✅ 3️⃣ UserManager 설정
    objects = UserManager()


    USERNAME_FIELD = 'email'  # 로그인 시 email 사용  // 미설정시 username 미입력 에러 발생 // username으로 설정 후 db_column을 email로 설정하면 기본 내장된 username 모델 사용 가능 - 커스텀 모델 지정 안해도 됨
    REQUIRED_FIELDS = [] # 필수 지정 모델들 넣어주면 superuser(관리자 계정) 생성 시 필수 입력 필드가 됨

    def __str__(self):
        return self.email



class SocialAccount(models.Model):
    """
    소셜 로그인 계정 정보 모델
    """
    member_id = models.OneToOneField('User', on_delete=models.CASCADE, related_name='social_account', verbose_name="회원 ID")
    login_id = models.CharField(max_length=255, unique=True, verbose_name="로그인 ID")  # 이메일 또는 소셜 ID 저장 가능
    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES, verbose_name="소셜 제공자")
    provider_id = models.CharField(max_length=255, unique=True, verbose_name="소셜 제공자 ID")  # 각 소셜 플랫폼에서 제공하는 고유 ID
    access_token = models.TextField(verbose_name="액세스 토큰")  # 소셜 로그인 액세스 토큰
    refresh_token = models.TextField(null=True, blank=True, verbose_name="리프레시 토큰")  # 선택적 저장
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active', verbose_name="상태")
    login_modified_dt = models.DateTimeField(auto_now=True, verbose_name="로그인 수정일")
    login_created_dt = models.DateTimeField(auto_now_add=True, verbose_name="로그인 생성일")


    def __str__(self):
        return f"{self.member_id} - {self.provider}"

