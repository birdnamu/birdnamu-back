#journal/urls.py
from django.urls import path
from .views import *

""" 필터 예시
GET /api/posts/?author=<user_id>&category=selected_bird
GET /api/posts/?author=1&category=bird_watching
"""

urlpatterns = [
    path('posts/', PostListCreateView.as_view(), name='journal-list-create'),
    path('posts/<int:pk>/', PostDetailView.as_view(), name='journal-detail'),
    path('posts/<int:pk>/like/', like_post, name='like_journal'),
    path('comments/', CommentListCreateView.as_view(), name='journal-comment-list-create'),
    path('comments/<int:pk>/', CommentDetailView.as_view(), name='journal-comment-detail'),
]