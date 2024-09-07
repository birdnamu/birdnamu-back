# todo/views.py
from django_filters.rest_framework import DjangoFilterBackend

from rest_framework import generics, permissions
from rest_framework.generics import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Todo
from .serializers import *
from .permissions import *

class TodoListView(generics.ListAPIView):
  queryset = Todo.objects.all()
  serializer_class = TodoSimpleSerializer
  permission_classes = [permissions.IsAuthenticatedOrReadOnly]
  filter_backends = [DjangoFilterBackend]
  filterset_fields = ['author', 'due_date', 'complete']
  """ def get_queryset(self):
    return Todo.objects.filter(author=self.request.user) """

class TodoCreateView(generics.CreateAPIView):
  queryset = Todo.objects.all()
  serializer_class = TodoCreateSerializer
  permission_classes = [permissions.IsAuthenticatedOrReadOnly]
  def perform_create(self, serializer):
    serializer.save(author=self.request.user)

class TodoDetailView(generics.RetrieveUpdateDestroyAPIView):
  queryset = Todo.objects.all()
  serializer_class = TodoDetailSerializer
  permission_classes = [IsAuthorOrReadOnly]
  """ def get_queryset(self):
    return Todo.objects.filter(author=self.request.user) """