#journal/permissions.py
from rest_framework import permissions

class IsAuthorOrReadOnly(permissions.BasePermission):
    """
    작성자만 수정 및 삭제 가능하고, 나머지는 읽기 전용 권한을 가진다.
    """
    def has_object_permission(self, request, view, obj):
        # 읽기 권한은 모든 요청에 대해 허용된다.
        if request.method in permissions.SAFE_METHODS:
            return True
        # 작성자만 수정 및 삭제 가능
        return obj.author == request.user