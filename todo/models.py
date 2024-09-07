#todo/models.py
from django.db import models
from django.conf import settings

# Create your models here.
class Todo(models.Model):
  author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="todo")
  title = models.CharField(max_length=100)
  description = models.TextField(max_length=255, blank=True, null=True)
  due_date = models.DateTimeField(blank=False, null=False)
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)
  complete = models.BooleanField(default=False)
  important = models.BooleanField(default=False)
  def __str__(self):
    return self.title