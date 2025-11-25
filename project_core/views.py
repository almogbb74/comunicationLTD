import re
import time

from django.contrib.auth import authenticate, login, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.http import HttpResponsePermanentRedirect, HttpResponseRedirect, HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.models import User  # Django's built-in User model
from django.contrib import messages  # For showing error/success messages
from .validators import validate_password_rules, load_password_config, validate_password_history
from enums.password_validation_enum import PasswordValidationEnum

MINUTE = 60


def auth_page(request) -> HttpResponsePermanentRedirect | HttpResponseRedirect | HttpResponse:
    # This 'context' dictionary will be passed to the template
    # It helps us re-open the 'Register' tab if validation fails, and also provides password rules
    config = load_password_config()
    password_rules = {
        'length': config.get('PASSWORD_LENGTH'),
        'uppercase': config.get('REQUIRE_UPPERCASE'),
        'lowercase': config.get('REQUIRE_LOWERCASE'),
        'digit': config.get('REQUIRE_DIGITS'),
        'special': config.get('REQUIRE_SPECIAL_CHARS')
    }
    context = {
        'show_register': False,
        'password_rules': password_rules
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
                password_validation = validate_password_rules(password)
            else:
                password_validation = PasswordValidationEnum.PASSWORD_INVALID_DEFAULT
            # VALIDATION ENDS

            # Check if any errors occurred
            if not errors and password_validation == PasswordValidationEnum.PASSWORD_VALID:
                # No errors found. Create the user.
                # This uses Django's default hasher (PBKDF2).
                user = User.objects.create_user(username=username, email=email, password=password)
                user.save()

                messages.success(request, 'Registration successful! You can now log in.')
                return redirect('auth_page')  # Redirect back to the same page

            else:
                # Errors were found
                # Show all validation errors to the user
                if password_validation == PasswordValidationEnum.PASSWORD_IS_IN_DICTIONARY:
                    errors.append('Your password cannot contain a commonly used word or phrase.')
                for error in errors:
                    messages.error(request, error)

        elif 'login_form' in request.POST:
            username = request.POST.get('username')
            password = request.POST.get('password')

            config = load_password_config()
            max_attempts = config.get('LOGIN_ATTEMPTS_MAX')
            lockout_duration = config.get('LOCKOUT_DURATION_IN_MIN') * MINUTE  # 15 minutes in seconds

            # Check if currently locked out
            lockout_timestamp = request.session.get('lockout_timestamp')

            if lockout_timestamp:
                current_time = time.time()
                if current_time - lockout_timestamp < lockout_duration:
                    # Still locked! Calculate remaining time.
                    remaining_seconds = lockout_duration - (current_time - lockout_timestamp)
                    minutes_left = int(remaining_seconds // MINUTE) + 1
                    messages.error(request, f'Account locked. Try again in {minutes_left} minutes.')
                    return render(request, 'authentication_page.html', context)
                else:
                    # Time has passed! Reset everything.
                    request.session['login_attempts'] = 0
                    request.session['lockout_timestamp'] = None

            # Check attempts count
            login_attempts = request.session.get('login_attempts', 0)

            # If we are at the limit but don't have a timestamp yet (edge case), set it now
            if login_attempts >= max_attempts and not lockout_timestamp:
                request.session['lockout_timestamp'] = time.time()
                messages.error(request, f'Login is now locked for {lockout_duration / MINUTE} minutes.')
                return render(request, 'authentication_page.html', context)

            # Attempt Authentication
            user = authenticate(request, username=username, password=password)

            if user is not None:
                # SUCCESS - Clear all counters and timers
                login(request, user)
                request.session['login_attempts'] = 0
                request.session['lockout_timestamp'] = None
                return redirect('main_screen')
            else:
                # FAILURE
                login_attempts += 1
                request.session['login_attempts'] = login_attempts

                if login_attempts >= max_attempts:
                    # Just hit the limit! Lock it down.
                    request.session['lockout_timestamp'] = time.time()
                    messages.error(request,
                                   f'Invalid credentials. Login is now locked for {lockout_duration / MINUTE} minutes.')
                else:
                    remaining = max_attempts - login_attempts
                    messages.error(request, f'Invalid credentials. {remaining} attempts remaining.')

    # This handles all GET requests (i..e., just loading the page)
    return render(request, 'authentication_page.html', context)


@login_required(login_url='auth_page')  # Protects this view
def main_screen_view(request):
    config = load_password_config()
    password_rules = {
        'length': config.get('PASSWORD_LENGTH'),
        'uppercase': config.get('REQUIRE_UPPERCASE'),
        'lowercase': config.get('REQUIRE_LOWERCASE'),
        'digit': config.get('REQUIRE_DIGITS'),
        'special': config.get('REQUIRE_SPECIAL_CHARS')
    }

    # Send the rules to the template
    context = {
        'password_rules': password_rules
    }
    return render(request, 'main_screen.html', context)


@login_required(login_url='auth_page')
def change_password_view(request):
    if request.method != 'POST':  # Only process POST requests
        return redirect('main_screen')

    config = load_password_config()
    history_count = config.get('PASSWORD_HISTORY_COUNT')

    current_password = request.POST.get('old_password')
    new_password = request.POST.get('new_password')
    confirm_password = request.POST.get('confirm_password')
    user: User = request.user

    if not user.check_password(current_password):  # Check if current password is correct
        messages.error(request, "Your old password was incorrect.")
        return redirect('main_screen')

    if new_password != confirm_password:  # Check new passwords match
        messages.error(request, "New passwords do not match.")
        return redirect('main_screen')

    password_validation = validate_password_rules(new_password)  # Validate password complexity
    if password_validation != PasswordValidationEnum.PASSWORD_VALID:
        if password_validation == PasswordValidationEnum.PASSWORD_IS_IN_DICTIONARY:
            messages.error(request, 'Your new password cannot contain a commonly used word or phrase.')
        return redirect('main_screen')

    password_history_validation = validate_password_history(user, new_password, history_count)  # Check password history

    if password_history_validation == PasswordValidationEnum.PASSWORD_PREVIOUSLY_USED:
        messages.error(request, f'You cannot reuse one of your last {history_count} passwords.')
        return redirect('main_screen')

    user.set_password(new_password)  # Update user password
    user.save()
    update_session_auth_hash(request, user)

    messages.success(request, "Your password was successfully updated!")
    return redirect('main_screen')
