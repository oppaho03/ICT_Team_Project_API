from django.contrib import admin
from .models import User, SocialAccount

#[장고 관리자화면에서 UI추가하기]
class UserSearch(admin.ModelAdmin):#ModelAdmin 상속
    search_fields = ['name','email'] # 검색 필드 나열.단, 모델의 필드명과 일치해야 한다 (name과 email로 검색 가능)

admin.site.register(User,UserSearch)

class SocialUserSearch(admin.ModelAdmin):#ModelAdmin 상속
    search_fields = ['member_id','provider'] # 검색 필드 나열.단, 모델의 필드명과 일치해야 한다

admin.site.register(SocialAccount,SocialUserSearch) # 장고 관리자에 등록

