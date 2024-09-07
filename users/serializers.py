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
""" from .models import CustomUser 대신에... 아래처럼 쓸 수도 있음
from django.contrib.auth import get_user_model
CustomUser = get_user_model()
"""
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


""" validated_data['설명']
  - 출처: rest_framework의 serilaizer
  - serializer.Serializer, serializer.ModelSerializer 상속 클래스에서 사용 가능
drf에서 시리얼라이저가 데이터를 검증한 후, 유효한 데이터만 담고 있는 dictionary이다.
클라이언트로부터 받은 입력data를 검증하고 그 결과로 생성된 유효한 데이터가 validated_data에 저장된다.

시리얼라이저 클래스에 정의된 필드 이름을 Key로, 필드의 입력값을 Value로 가지는 구조.
모델 인스턴스 생성/수정될 때 사용
"""
""" def save(self, request): # 이 코드는 adapter.py 에서 쓴다.
    user = super().save(request)
    user.fullname = self.validated_data.get("fullname", "")
    user.gender = self.validated_data.get("gender", "")
    user.birthdate = self.validated_data.get("birthdate", None)
    user.image= self.validated_data.get("image", "dafault.jpg")
    user.save()
    return user """
""" attrs 변수명의 의미: 
    attrs is the Python package that gives you a class decorator and a way to declaratively define the attributes on that class
"""

class CustomLoginSerializer(LoginSerializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    def authenticate(self, **kwargs):
        return super().authenticate(**kwargs)
    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')
        if username and password:
            user = self.authenticate(username=username, password=password)
            if not user:
                msg = _('Unable to log in with provided credentials.')
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = _('Must include "username" and "password".')
            raise serializers.ValidationError(msg, code='authorization')
        attrs['user'] = user
        return attrs

# 아래는 실패한 CustomLoginSerializer 코드들...
""" class CustomLoginSerializer(LoginSerializer):
    def validate(self, attrs): 
        data = super().validate(attrs)
        user = self.get_user()
        refresh = RefreshToken.for_user(user)
        # jwt 토큰을 포함한 데이터 반환
        data.update({
            'refresh_token': str(refresh),
            'access_token': str(refresh.access_token),
        })
        return data
    def get_user(self):
        username = self.initial_data.get('username')
        email = self.initial_data.get('email')
        password = self.initial_data.get('password')
        user = self.get_auth_user(username, email, password)
        if not user:
            raise serializers.ValidationError('Unable to log in with provided credentials.')
        return user """
""" class CustomLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    token = serializers.CharField(max_length=40, read_only=True)
    
    def validate(self, attrs):
        username = attrs.get("username")
        password = attrs.get("password", None)
        user = authenticate(username=username, password=password)
        if user is None:
            return {'username': 'None'}
        try: payload  """

# UserInfoSerializer 수정 전 코드...
""" class UserInfoSerializer(serializers.ModelSerializer):
    username = serializers.CharField(read_only=True)
    fullname = serializers.CharField(read_only=True)
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
    class Meta:
        model = User
        fields = ("username", "email","password1", "password2", "fullname", "gender", "birthdate", "image", "bio")
 """


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
    
    """ def validate(self, data):
        if data["password1"] != data["password2"]:
            raise serializers.ValidationError(
                {"password": "Password fields do not match."}
            )
        return data
    기존 코드: data["password1"]과 data["password2"]를 사용하여 필드를 가져옵니다. 이 방법은 data 딕셔너리에서 해당 키가 없을 때 KeyError를 발생시킬 수 있습니다.
    수정된 코드: data.get("password1")과 data.get("password2")를 사용하여 값을 가져옵니다. get() 메소드는 키가 없을 경우 None을 반환하므로, KeyError를 방지할 수 있습니다. 이는 코드의 안정성을 높여줍니다.    
    """        
    
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