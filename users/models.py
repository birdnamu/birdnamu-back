# users/models.py

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings # Bird 모델의 settings.AUTH_USER_MODEL 가져오기 위해

class CustomUser(AbstractUser):
  fullname = models.CharField(max_length=150, blank=False, null = False)
  gender = models.CharField(max_length=10, choices=[('M', 'Male'), ('F', "Female")], blank=False, null=True)
  birthdate = models.DateField(blank=True, null=True)
  image = models.ImageField(upload_to='profile/', default='default.jpg', )
  bio = models.TextField(max_length=200, blank=True, null=True)

class Bird(models.Model):
  GENDER_CHOICES = [
    ('M', 'Male'),
    ('F', 'Female'),
    ('U', 'Unknown'),
  ]
  owner = models.ForeignKey(
    settings.AUTH_USER_MODEL,
    on_delete=models.CASCADE,
    related_name='birds',
    blank=True,
    null=False
  )
  name = models.CharField(max_length=100)
  gender = models.CharField(max_length=10, choices=GENDER_CHOICES, default='U')
  birthdate = models.DateField(blank=True, null=True)
  breed = models.CharField(max_length=100, blank=True, null = True)
  personality = models.TextField(max_length=400, blank=True, null=True)
  image = models.ImageField(upload_to='bird_profile/', default='default.jpg')
  def __str__(self):
    return self.name