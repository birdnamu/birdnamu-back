#users/permissions.py
from rest_framework import permissions

class CustomReadOnly(permissions.BasePermission):
    """
    커스텀 권한 클래스:
    - 조회 (GET 요청): 누구나 접근 가능
    - 생성 (POST 요청): 로그인한 사용자만 접근 가능
    - 수정 (PUT, PATCH 요청) 및 삭제 (DELETE 요청): 객체의 소유자(owner)만 접근 가능
    """

    def has_permission(self, request, view):
        # 모든 사용자가 GET 요청을 할 수 있도록 허용
        if request.method in permissions.SAFE_METHODS:
          return True

        # POST 요청은 로그인한 사용자만 허용
        if request.method == 'POST':
          #return True
          return request.user and request.user.is_authenticated

        # PUT, PATCH, DELETE 요청은 객체의 소유자만 허용
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        # 모든 사용자가 GET 요청을 할 수 있도록 허용
        if request.method in permissions.SAFE_METHODS:
            return True

        # PUT, PATCH, DELETE 요청은 객체의 소유자만 허용
        return obj.owner == request.user

