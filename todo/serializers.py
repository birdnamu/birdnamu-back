#todo/serializers.py
from rest_framework import serializers
from .models import Todo

class TodoSimpleSerializer(serializers.ModelSerializer):
  class Meta:
    model = Todo
    fields = ('id', 'author', 'title', 'due_date', 'complete', 'important')

class TodoCreateSerializer(serializers.ModelSerializer):
  class Meta:
    model = Todo
    fields = ('title', 'description', 'due_date', 'important')

class TodoDetailSerializer(serializers.ModelSerializer):
  class Meta:
    model = Todo
    fields = ('id', 'title', 'description', 'due_date', 'complete', 'important')
