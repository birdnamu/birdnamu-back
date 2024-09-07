#users/adapter.py
# Abstract User 모델에서 추가한 필드가 회원가입시 저장이 안 되는 문제 해결

from allauth.account.adapter import DefaultAccountAdapter

class CustomUserAdapter(DefaultAccountAdapter):
  def save_user(self, request, user, form, commit=False):
    user = super().save_user(request, user, form, commit)
    data = form.cleaned_data
    user.fullname = data.get("fullname", "")
    user.gender = data.get("gender", "")
    user.birthdate = data.get("birthdate", None)
    user.image= data.get("image", "default.jpg")
    user.save()
    return user