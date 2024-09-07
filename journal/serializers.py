#journal/serializers.py
from rest_framework import serializers
from .models import Post, Comment
from users.models import Bird

class CommentSerializer(serializers.ModelSerializer):
    author = serializers.ReadOnlyField(source='author.username')

    class Meta:
        model = Comment
        fields = ['id', 'post', 'author', 'content', 'created_at', 'updated_at']



class PostSerializer(serializers.ModelSerializer):
    author = serializers.ReadOnlyField(source='author.username')
    likes_count = serializers.SerializerMethodField()
    is_liked = serializers.SerializerMethodField()
    comments = CommentSerializer(many=True, read_only=True) # Post에 달린 댓글을 포함
    
    class Meta:
        model = Post
        fields = ['id', 'author', 'title', 'date', 'content', 'created_at', 'updated_at', 'likes_count', 'is_liked', 'image', 'category', 'comments']
    
    def create(self, validated_data):
        # 작성자가 소유한 반려조의 이름을 카테고리로 사용
        user = self.context['request'].user
        birds = Bird.objects.filter(owner=user)
        categories = [bird.name for bird in birds]
        # 사용자가 소유한 Bird가 없으면 기본 카테고리 처리
        if not categories:
            raise serializers.ValidationError("등록된 반려조가 없습니다. 카테고리를 선택할 수 없습니다.")
        if validated_data['category'] not in categories:
            raise serializers.ValidationError("해당 카테고리는 유효하지 않습니다.")
        return super().create(validated_data)
    def get_likes_count(self, obj):
        return obj.likes.count()
    def get_is_liked(self, obj):
        request = self.context.get('request')
        return request.user in obj.likes.all()