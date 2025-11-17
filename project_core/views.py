from django.shortcuts import render, redirect
from django.contrib.auth.models import User  # Django's built-in User model
from django.contrib import messages  # For showing error/success messages
from .validators import validate_password_rules  # My password validator
import re


def auth_page(request):
    # This 'context' dictionary will be passed to the template
    # It helps us re-open the 'Register' tab if validation fails
    context = {
        'show_register': False
    }

    if request.method == 'POST':
        # Check which form was submitted. We'll check for the 'register_form' button name.
        if 'register_form' in request.POST:
            # REGISTRATION ATTEMPT
            context['show_register'] = True  # Tell the template to keep the register tab open

            # Get data from the form
            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')
            password_confirm = request.POST.get('password_confirm')

            # STARTING VALIDATION HERE
            errors = []

            # Check for empty fields FIRST
            if not username:
                errors.append("Username is required.")
            if not email:
                errors.append("Email is required.")
            if not password:
                errors.append("Password is required.")
            if not password_confirm:
                errors.append("Please confirm your password.")

            # Only run other checks if the fields aren't empty
            if username and User.objects.filter(username=username).exists():
                errors.append("Username is already taken.")

            if email and User.objects.filter(email=email).exists():
                errors.append("Email is already registered.")

            if password and password != password_confirm:
                errors.append("Passwords do not match.")

            if email:
                # Check email format using a simple regex
                email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                if not re.match(email_regex, email):
                    errors.append("Please enter a valid email address.")
                # Check if email exists only if the format is valid
                elif User.objects.filter(email=email).exists():
                    errors.append("Email is already registered.")

            # Only validate password rules if there is a password to check
            if password:
                password_errors = validate_password_rules(password)
                errors.extend(password_errors)  # Add all password errors to our list

            # VALIDATION ENDS

            # Check if any errors occurred
            if not errors:
                # No errors found. Create the user.
                # This uses Django's default hasher (PBKDF2) for now.
                user = User.objects.create_user(username=username, email=email, password=password)
                user.save()

                messages.success(request, 'Registration successful! You can now log in.')
                return redirect('auth_page')  # Redirect back to the same page

            else:
                # Errors were found
                # Show all validation errors to the user
                for error in errors:
                    messages.error(request, error)

        elif 'login_form' in request.POST:
            # TODO: Implement login logic here later
            messages.error(request, 'Login logic is not implemented yet.')

    # This handles all GET requests (i..e., just loading the page)
    return render(request, 'authentication_page.html', context)
