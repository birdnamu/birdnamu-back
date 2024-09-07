from django.db import models
from django.conf import settings

class Post(models.Model):
  author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='board')
  title = models.CharField(max_length=255)
  #category 필드 없음
  question = models.BooleanField(default=False)
  content = models.TextField()
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)
  likes = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='like_board', blank=True)
  image = models.ImageField(upload_to='board/',blank=True, null=True)  

class Comment(models.Model):
  post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
  author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='board_comments')
  content = models.TextField()
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)
  likes = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='like_comments', blank=True)

  def __str__(self):
    return f'Comment by {self.author} on {self.post}'