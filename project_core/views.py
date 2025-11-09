from django.shortcuts import render


# This function will render our login page
def auth_page(request):
    # This tells Django to find 'authentication_page.html'
    # inside your 'templates' folder and show it.
    return render(request, 'authentication_page.html')
