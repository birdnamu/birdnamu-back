#board/serializers.py
from rest_framework import serializers

from .models import *

class CommentSerializer(serializers.ModelSerializer):
  author = serializers.ReadOnlyField(source='author.username')
  likes_count = serializers.SerializerMethodField()
  is_liked = serializers.SerializerMethodField()
  class Meta:
    model = Comment
    fields = ['id', 'post', 'author', 'content', 'created_at', 'updated_at', 'likes_count', 'is_liked']
  def get_likes_count(self, obj):
    return obj.likes.count()
  def get_is_liked(self, obj):
    request = self.context.get('request')
    return request.user in obj.likes.all()


class PostSerializer(serializers.ModelSerializer):
  author = serializers.ReadOnlyField(source='author.username')
  likes_count = serializers.SerializerMethodField()
  is_liked = serializers.SerializerMethodField()
  comments = CommentSerializer(many=True, read_only=True) # Post에 달린 댓글을 포함
  class Meta:
    model = Post
    fields = ['id', 'author', 'title', 'question', 'content', 'created_at', 'updated_at', 'likes_count', 'is_liked', 'comments']
  def get_likes_count(self, obj):
    return obj.likes.count()
  def get_is_liked(self, obj):
    request = self.context.get('request')
    return request.user in obj.likes.all()