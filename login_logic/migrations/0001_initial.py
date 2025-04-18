# Generated by Django 5.1.5 on 2025-03-19 08:13

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('email', models.EmailField(max_length=30, unique=True, verbose_name='이메일')),
                ('password', models.CharField(max_length=128, verbose_name='비밀번호')),
                ('role', models.CharField(default='user', max_length=30, verbose_name='역할')),
                ('name', models.CharField(max_length=50, verbose_name='이름')),
                ('nickname', models.CharField(blank=True, max_length=50, null=True, unique=True, verbose_name='닉네임')),
                ('birth', models.DateField(blank=True, null=True, verbose_name='생년월일')),
                ('gender', models.CharField(blank=True, choices=[('male', 'Male'), ('female', 'Female'), ('screct', 'Screct')], max_length=10, null=True, verbose_name='성별')),
                ('contact', models.CharField(max_length=15, verbose_name='연락처')),
                ('address', models.TextField(blank=True, null=True, verbose_name='주소')),
                ('token', models.TextField(blank=True, max_length=255, null=True, verbose_name='인증 토큰(refresh)')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='가입일')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='업데이트일')),
                ('status', models.CharField(choices=[('active', 'Active'), ('inactive', 'Inactive'), ('banned', 'Banned')], default='active', max_length=20, verbose_name='상태')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='SocialAccount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('login_id', models.CharField(max_length=255, unique=True, verbose_name='로그인 ID')),
                ('provider', models.CharField(choices=[('google', 'Google'), ('kakao', 'Kakao'), ('naver', 'Naver')], max_length=20, verbose_name='소셜 제공자')),
                ('provider_id', models.CharField(max_length=255, unique=True, verbose_name='소셜 제공자 ID')),
                ('access_token', models.TextField(verbose_name='액세스 토큰')),
                ('refresh_token', models.TextField(blank=True, null=True, verbose_name='리프레시 토큰')),
                ('status', models.CharField(choices=[('active', 'Active'), ('inactive', 'Inactive'), ('banned', 'Banned')], default='active', max_length=20, verbose_name='상태')),
                ('login_modified_dt', models.DateTimeField(auto_now=True, verbose_name='로그인 수정일')),
                ('login_created_dt', models.DateTimeField(auto_now_add=True, verbose_name='로그인 생성일')),
                ('member_id', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='social_account', to=settings.AUTH_USER_MODEL, verbose_name='회원 ID')),
            ],
        ),
    ]
