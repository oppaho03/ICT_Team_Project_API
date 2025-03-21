from django.core.mail import send_mail
import random


def generate_auth_code(length=6):
    return ''.join(random.choices('0123456789', k=length))

def send_verification_code(email, code):
    subject = "VITA 이메일 인증 코드"
    message = f"인증 코드: {code}\n5분 이내에 입력해주세요."
    send_mail(subject, message, 'your-email@gmail.com', [email])


