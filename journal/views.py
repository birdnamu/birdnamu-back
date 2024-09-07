#journal/views.py
from django_filters.rest_framework import DjangoFilterBackend #ModelViewSet할 때 썼던 필터링 설정
from rest_framework import generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Post, Comment
from .serializers import PostSerializer, CommentSerializer
from .permissions import IsAuthorOrReadOnly

class PostListCreateView(generics.ListCreateAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['author', 'category']
    
    def perform_create(self, serializer):
        serializer.save(author=self.request.user)

class PostDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    permission_classes = [IsAuthorOrReadOnly]

class CommentListCreateView(generics.ListCreateAPIView):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)

class CommentDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [IsAuthorOrReadOnly]

''' likes 필드 & 함수형 뷰 like_post
  likes 필드는 ManyToMany필드이다.
  초기에 실행하면 [] 라는 빈 리스트 형태로 반환될 것이다.
  likes는 리스트 형태로 유저 데이터를 담고 있을 수 있으며,
  우리는 담겨 있는 유저들의 목록을 확인해,
    (1) 좋아요를 누른 것인지
    (2) 한 번 더 눌러 취소한 것인지
  처리하는 뷰를 간단히 구현하였다.
'''
''' url 설정하는 법 ?
    => viewset 의 router로
'''
@api_view(['GET']) # GET 요청 / 함수형 뷰
@permission_classes([IsAuthenticated]) # 권한이 필요함을 설정하는 데코레이터, 회원가입한 user라면 모두 가능함=> IsAuthenticated로 설정
def like_post(request,pk): # 좋아요 기능
    post = get_object_or_404(Post, pk=pk)
    if post.likes.filter(id=request.user.id).exists():# post.likes.에 request.user가 있다면,
    # if request.user in post.likes.all(): # post.likes.all() 에 request.user가 있다면,
        post.likes.remove(request.user) # request.user 를 지우기
        return Response({'status': 'ok (remove like on the post)'})
    else: # 없다면,
        post.likes.add(request.user) # request.user 를 추가하기
    return Response({'status': 'ok (add like on the post)'})