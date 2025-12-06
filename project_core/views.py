import re
import time
import logging

from django.contrib.auth import authenticate, login, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.http import HttpResponsePermanentRedirect, HttpResponseRedirect, HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.utils import timezone

from .models import PasswordResetToken
from .validators import validate_password_rules, load_password_config, validate_password_history
from enums.password_validation_enum import PasswordValidationEnum
from django.core.exceptions import ObjectDoesNotExist

MINUTE = 60
LOGGER = logging.getLogger('communication_ltd')


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


def request_password_reset(request):
    if request.method == 'POST':
        email = request.POST.get('reset_email')
        try:  # Check if user exists
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:
            # Security-wise we won't reveal if user exists.
            # We pretend it worked to prevent user enumeration.
            # Render Step 2 (Enter Token) as if an email was sent.
            return render(request, 'password_reset_templates/password_reset_step2.html', {'email': email})

        # Generate and save token
        plain_token = PasswordResetToken.generate_token()

        # Create or update token for user (invalidate old ones)
        PasswordResetToken.objects.filter(user=user).delete()
        reset_token = PasswordResetToken(user=user)
        reset_token.save_token(plain_token)

        send_mail(
            subject='Password Reset Token',
            message=f'Hello {user.username},\n\nYour password reset token is: {plain_token}\n\nUse this token to verify your identity.',
            from_email='system@comunication_ltd.com',
            recipient_list=[email],
            fail_silently=False,
        )
        #  Render Step 2 (Enter Token)
        return render(request, 'password_reset_templates/password_reset_step2.html', {'email': email})

    # If GET request (clicking the link), show the page
    return render(request, 'password_reset_templates/password_reset_step1.html')


def verify_reset_token(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        token = request.POST.get('token')
        config = load_password_config()
        password_rules = {
            'length': config.get('PASSWORD_LENGTH'),
            'uppercase': config.get('REQUIRE_UPPERCASE'),
            'lowercase': config.get('REQUIRE_LOWERCASE'),
            'digit': config.get('REQUIRE_DIGITS'),
            'special': config.get('REQUIRE_SPECIAL_CHARS')
        }

        try:
            user = User.objects.get(email=email)
            reset_token = PasswordResetToken.objects.get(user=user)

            # Check expiration (15 minutes = 900 seconds)
            if (timezone.now() - reset_token.created_at).total_seconds() > 900:
                messages.error(request, "Token expired.")
                return redirect('auth_page')

            if reset_token.verify(token):
                # Token valid! Render Step 3 (Set New Password)
                return render(request, 'password_reset_templates/password_reset_step3.html',
                              {'email': email, 'token': token, 'password_rules': password_rules})
            else:
                messages.error(request, "Invalid token.")
                return render(request, 'password_reset_templates/password_reset_step2.html', {'email': email})

        except ObjectDoesNotExist:
            messages.error(request, "Invalid request.")
            return redirect('auth_page')

    return redirect('auth_page')  # If GET request, redirect to auth page


def reset_password_confirm(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        token = request.POST.get('token')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        config = load_password_config()
        history_count = config.get('PASSWORD_HISTORY_COUNT')
        password_rules = {
            'length': config.get('PASSWORD_LENGTH'),
            'uppercase': config.get('REQUIRE_UPPERCASE'),
            'lowercase': config.get('REQUIRE_LOWERCASE'),
            'digit': config.get('REQUIRE_DIGITS'),
            'special': config.get('REQUIRE_SPECIAL_CHARS')
        }

        # Re-verify everything for security (stateless check)
        try:
            user = User.objects.get(email=email)
            reset_token = PasswordResetToken.objects.get(user=user)

            if not reset_token.verify(token):
                messages.error(request, "Invalid token.")
                return redirect('auth_page')

            password_validation = validate_password_rules(new_password)  # Validate password complexity
            if password_validation != PasswordValidationEnum.PASSWORD_VALID:
                if password_validation == PasswordValidationEnum.PASSWORD_IS_IN_DICTIONARY:
                    messages.error(request, 'Your new password cannot contain a commonly used word or phrase.')
                return render(request, 'password_reset_templates/password_reset_step3.html',
                              {'email': email, 'token': token, 'password_rules': password_rules})

            password_history_validation = validate_password_history(user, new_password,
                                                                    history_count)  # Check password history

            if password_history_validation == PasswordValidationEnum.PASSWORD_PREVIOUSLY_USED:
                messages.error(request, f'You cannot reuse one of your last {history_count} passwords.')
                return render(request, 'password_reset_templates/password_reset_step3.html',
                              {'email': email, 'token': token, 'password_rules': password_rules})

            if new_password != confirm_password:
                messages.error(request, "Passwords do not match.")
                return render(request, 'password_reset_templates/password_reset_step3.html',
                              {'email': email, 'token': token, 'password_rules': password_rules})

            user.set_password(new_password)  # Success! Update password
            user.save()

            reset_token.delete()  # Invalidate the used token
            messages.success(request, "Password reset successful! You can now login.")
            return redirect('auth_page')

        except ObjectDoesNotExist:
            messages.error(request, "Error resetting password.")
            return redirect('auth_page')

    return redirect('auth_page')  # If GET request, redirect to auth page
