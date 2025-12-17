from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # It tells Django that when someone visits the main page ('')
    # it should run the 'auth_page' function from views.py
    path('', views.auth_page, name='auth_page'),
    path('system/', views.main_screen_view, name='main_screen'),

    # Logout Logic
    # This uses Django's built-in logout functionality.
    # 'next_page' tells Django where to redirect after logging out (back to login page).
    path('logout/', auth_views.LogoutView.as_view(next_page='auth_page'), name='logout'),

    path('change-password/', views.change_password_view, name='change_password'),
    path('customers-view/', views.customers_view, name='customers_view'),

    # Password Reset Request
    # Added for future implementation of the "Forgot Password" feature
    path('password_reset/', views.request_password_reset, name='password_reset_request'),
    path('verify_token/', views.verify_reset_token, name='password_reset_verify'),
    path('new_password/', views.reset_password_confirm, name='password_reset_confirm'),

]
