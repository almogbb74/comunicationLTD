from django.contrib import admin
from django.urls import path
from . import views  # <-- This imports your new views.py file

urlpatterns = [
    path('admin/', admin.site.urls),

    # This is the important line:
    # It tells Django that when someone visits the main page ('')
    # it should run the 'auth_page' function from our views.py
    path('', views.auth_page, name='auth_page'),
]
