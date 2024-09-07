from django.contrib.auth import get_user_model
from django_filters.rest_framework import DjangoFilterBackend

from rest_framework import generics, permissions, viewsets, status
from rest_framework.response import Response

from dj_rest_auth.views import LoginView #, LogoutView
#jwt token 특성상 logout은 굳이 API로 구현할 필요가 없다. FE에서 직접 token을 삭제(쿠키 해제 등)를 하는게 더 좋다. 
from dj_rest_auth.registration.views import RegisterView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Bird
from .serializers import *
from .permissions import CustomReadOnly

User = get_user_model()

class CustomRegisterView(RegisterView):
  serializer_class = CustomRegisterSerializer

class CustomLoginView(LoginView):
  serializer_class = CustomLoginSerializer
  def get_response(self):
    # 로그인 성공 시, 커스텀 응답을 반환하는 예제
    response = super().get_response()
    user = self.user
    refresh = RefreshToken.for_user(user)
    response.data['user'] = {
      'username': user.username,
      'fullname': user.fullname,
      'email': user.email,
      'gender': user.gender,
      'birthdate': user.birthdate,
      'image': user.image.url if user.image else None,
      'bio': user.bio,
    }
    response.data['access_token'] = str(refresh.access_token)
    response.data['refresh_token'] = str(refresh)
    return response

class UserInfoView(generics.RetrieveAPIView):
  permission_classes = [permissions.IsAuthenticated]
  serializer_class = UserInfoSerializer
  def get_object(self):
    return self.request.user
    #챗지피티가 바로 윗줄 코드가 원래 return self.get_object() <=요거였는데 바꾸라 함. 로그인 된 사용자 객체를 반환해야 된대... 안 해봐서 모름

class UserUpdateView(generics.UpdateAPIView):
  permission_classes = [permissions.IsAuthenticated]
  serializer_class = UserUpdateSerializer
  def get_object(self):
    return self.request.user

class ProfileView(generics.RetrieveAPIView):
  queryset = User.objects.all()
  serializer_class = ProfileSerializer
  lookup_field = 'username'

""" class BirdCreateView(generics.CreateAPIView):
  queryset = Bird.objects.all()
  serializer_class = BirdSerializer
  permission_classes = [permissions.IsAuthenticated]
  def perform_create(self, serializer):
    serializer.save(owner=self.request.user)

class BirdListView(generics.ListAPIView):
  queryset = Bird.objects.all()
  serializer_class = BirdSerializer
  filter_backends = [DjangoFilterBackend]
  filterset_fields = ['owner']

class BirdDetailView(generics.RetrieveUpdateDestroyAPIView):
  queryset = Bird.objects.all()
  serializer_class = BirdSerializer
  permission_classes = [permissions.IsAuthenticated] """

class BirdViewSet(viewsets.ModelViewSet):
  queryset = Bird.objects.all()
  serializer_class = BirdSerializer
  permission_classes=[CustomReadOnly]
  filter_backends = [DjangoFilterBackend]
  filterset_fields = ['owner']
  def perform_create(self, serializer):
    serializer.save(owner=self.request.user)