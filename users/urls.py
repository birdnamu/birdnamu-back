# users/urls.py

from django.urls import path, include
from rest_framework import routers
from .views import *

router = routers.SimpleRouter()
router.register('birds',BirdViewSet)

# List http://127.0.0.1:8000/users/birds/
# Retrieve http://127.0.0.1:8000/users/birds/1/
# owner 필터링 http://127.0.0.1:8000/users/birds/?owner=<user_id>
# http://127.0.0.1:8000/users/birds/?owner=1

urlpatterns = router.urls + [
  path('register/', CustomRegisterView.as_view(), name='user_register'),
  path('login/', CustomLoginView.as_view(), name='user_login'),
  path('userinfo/', UserInfoView.as_view(), name='user_info'),
  path('userinfo/update/', UserUpdateView.as_view(), name='user_update'),
  path('profile/<str:username>/', ProfileView.as_view(), name='user_profile'),
]
