# todo/urls.py
from django.urls import path
from .views import *

''' 필터링 URL 예사
http://127.0.0.1:8000/todo/?author=<int:pk>
http://127.0.0.1:8000/todo/?author=1
http://127.0.0.1:8000/todo/?author=2&due_date=
http://127.0.0.1:8000/todo/?author=2&due_date=2024-09-07&complete=
'''

urlpatterns = [
  path('', TodoListView.as_view(), name='todo-list'),
  path('new/', TodoCreateView.as_view(), name='todo-create'),
  path('<int:pk>/', TodoDetailView.as_view(), name='todo-detail'),
]