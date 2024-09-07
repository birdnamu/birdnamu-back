# users/serializers.py

# .. pip install dj-rest-auth 를 해야한다. (rest-auth는 삭제)
from dj_rest_auth.registration.serializers import RegisterSerializer
from dj_rest_auth.serializers import LoginSerializer
from rest_framework import serializers

from rest_framework.validators import UniqueValidator
# validate_password 비밀번호 유효성 검사 수행 도구
from django.contrib.auth.password_validation import validate_password

#LoginSerializer 커스텀하기 위해 추가..
from django.utils.translation import gettext_lazy as _

from django.contrib.auth import get_user_model

from .models import Bird

User = get_user_model() # 순환 참조를 막기 위해 사용. Django 권장방식
# settings.py에서 지정한 AUTH_USER_MODEL을 가져온다.

class CustomRegisterSerializer(RegisterSerializer):
    fullname = serializers.CharField(required=True)
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())],
    )
    password1 = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
    )
    password2 = serializers.CharField(write_only=True, required=True)
    gender = serializers.ChoiceField(choices=[("M", "Male"), ("F", "Female")], required=True)
    birthdate = serializers.DateField(required=False)
    image = serializers.ImageField(required=False)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2", "fullname", "gender", "birthdate")

    def validate(self, data):
        if data["password1"] != data["password2"]:
            raise serializers.ValidationError(
                {"password": "Password fields do not match."}
            )
        return data

    def get_cleaned_data(self):
        cleaned_data = super().get_cleaned_data()
        cleaned_data["fullname"] = self.validated_data.get("fullname", "")
        cleaned_data["gender"] = self.validated_data.get("gender", "")
        cleaned_data["birthdate"] = self.validated_data.get("birthdate", None)
        cleaned_data["image"] = self.validated_data.get("image", "default.jpg")
        return cleaned_data

class UserInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("username", "email", "fullname", "gender", "birthdate", "image", "bio")

class UserUpdateSerializer(serializers.ModelSerializer):
    username = serializers.CharField(read_only=True)
    fullname = serializers.CharField(read_only=True)
    password1 = serializers.CharField(
        write_only=True,
        required=False,
        validators=[validate_password],
    )
    password2 = serializers.CharField(write_only=True, required=False)
    email = serializers.EmailField(required=False,)
    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2", "fullname", "gender", "birthdate", "image", "bio")
    def validate(self, data):
        password1 = data.get("password1")
        password2 = data.get("password2")
        
        if password1 and password2 and password1 != password2:
            raise serializers.ValidationError(
                {"password": "Password fields do not match."}
            )
        return data    
    
    def validate_email(self, value):
        user = self.context['request'].user
        if User.objects.exclude(pk=user.pk).filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value
    
    def update(self, instance, validated_data):
        password1 = validated_data.pop("password1", None)
        validated_data.pop("password2", None)
        for key, value in validated_data.items():
            setattr(instance, key, value)
        if password1:
            instance.set_password(password1)
        instance.save()
        return instance

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields =("username", "image", "bio")


class BirdSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bird
        fields = ['id', 'owner', 'name', 'gender', 'birthdate', 'breed', 'personality', 'image']




#users/views.py
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

class BirdViewSet(viewsets.ModelViewSet):
  queryset = Bird.objects.all()
  serializer_class = BirdSerializer
  permission_classes=[CustomReadOnly]
  filter_backends = [DjangoFilterBackend]
  filterset_fields = ['owner']
  def perform_create(self, serializer):
    serializer.save(owner=self.request.user)