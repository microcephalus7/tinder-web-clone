from django.urls import path
from . import views


urlpatterns = [
    path('', views.index, ),
    path('signin', views.signIn),
    path('token', views.tokenCheck),
    path("profile", views.profile)
]
