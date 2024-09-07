#board/urls.py
from django.urls import path
from .views import *

urlpatterns = [
  path('posts/', PostListCreateView.as_view(), name='board-list-create'),
  path('posts/<int:pk>', PostDetailView.as_view(), name='board-detail'),
  path('posts/<int:pk>/like/', like_post, name='like_board'),
  path('comments/',CommentListCrerateView.as_view(), name='board-comment-list-create'),
  path('comments/<int:pk>', CommentDetailView.as_view(), name='board-comment-detail'),
  path('comments/<int:pk>/like/', like_comment, name='like_comment'),
]