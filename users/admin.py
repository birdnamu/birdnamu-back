''' from django.contrib import admin 역할
django.contrib : django의 기본 관리자 인터페이스를 사용하기 위한 모듕
admin.py에서 관리자 페이지를 커스터마이징할 떄 사용한다.
'''
from django.contrib import admin
''' from django.contrib.auth.admin import UserAdmin 의 역할
기본 User 모델의 관리자 인터페이스를 확장하거나 커스터마이징할 때 사용하는 클래스
'''
from django.contrib.auth.admin import UserAdmin
''' .models import CustomUser 의 역할: 현재 앱(디렉토리)에 있는 models.py에서 Customuser 모델 가져오기. (AbstractUser 상속)
'''
from .models import CustomUser, Bird

'''CustomUserAdmin(UserAdmin)클래스 : UserAdmin 클래스를 상속받아 커스터마이징한 관리자 클래스
이 클래스를 통해 기본 사용자 모델의 관리자 인터페이스를 재정의한다.
'''
class CustomUserAdmin(UserAdmin):
  model = CustomUser
  ''' fieldsets & UserAdmin.fieldsets 설명:
    - fieldsets
      관리자 페이지에서 사용자 객체의 세부 정보 페이지를 표시할 때,
      어떤 필드를 어떤 순서로 보여줄지 경정하는 설정
    - UserAdmin.fieldsets
      기본 UserAdmin 클래스에서 제공하는 필드셋
    - +
      기본 필드셋에 추가로 새로운 필드셋을 덧붙이는 작업을 하는 연산자..
    - (괄호 안의 내용)
    fullname, gender, birthdate, imamge 필드를 추가한다.
    None의 의미: 필드셋에 별도의 제목이 없음을 의미한다.
  '''
  ''' fieldsets 와 add_fieldsets의 역할
      fieldsets : 관리자 admin 페이지에서 기존 사용자를 편집할 때 사용되는 필드 구성
      add_fieldsets: 관리자 admin 페이지에서 새로운 사용자를 추가할 때 사용되는 필드 구성
  '''
  fieldsets = UserAdmin.fieldsets + (
    (None, {'fields': ('fullname', 'gender', 'birthdate', 'image', 'bio')}),
  )
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Bird)
# 커스터마이징한 CustomUser 모델을 Django 관리자 사이트에 등록한다.
# 관리자 페이지에서 모델을 관리할 수 있게 된다.
# (CustomUser, CustomUserAdmin)
#  ==>> 앞서 정의한 CustomUserAdmin 클래스가 적용되어 CustomUser 모델의 관리 페이지가 커스터마이징된 형태로 표시되도록 한다.


''' 블로그 글에서 사용한 CustomUserAdmin 클래스
출처: https://velog.io/@qlgks1/django-user-customizing-jwt-token 

# admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

class CustomUserAdmin(UserAdmin):
    # 필드 순서 및 구성을 커스터마이징
    fieldsets = UserAdmin.fieldsets + (
        (None, {'fields': ('profile_pic', 'website_url')}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {
            'classes': ('wide',),
            'fields': ('profile_pic', 'website_url'),
        }),
    )

admin.site.register(CustomUser, CustomUserAdmin)

'''
''' 위의 블로그 글에서 사용한 CustomUserAdmin 클래스의 코드 설명
  - add_fieldsets:
    관리자 페이지에서 새로운 사용자를 추가할 때 사용할 필드셋을 정의합니다.
    
  - UserAdmin.add_fieldsets: 
    기본 사용자 추가 양식에서 제공되는 필드셋입니다.
    
  - + :
    기존 필드셋에 추가 필드를 더합니다.
    
  - {'classes': ('wide',), 'fields': ('profile_pic', 'website_url')} :
    - classes: HTML 클래스입니다. 여기서는 wide 클래스를 사용하여 넓은 레이아웃을 지정합니다.
    - fields: 사용자 추가 양식에 표시할 필드입니다. profile_pic과 website_url을 추가하고 있습니다.
'''