from datetime import date, datetime, timedelta, timezone
from urllib import response
from celery import shared_task
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.forms import ValidationError
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
from httplib2 import Authentication
from rest_framework import views, permissions, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError

from api.models import CustomUser, Habit, HabitLog
from api.tasks import send_email_reminder

from .serializers import HabitDetailSerializer, HabitLogSerializer, HabitSerializer, PasswordResetConfirmSerializer, PasswordResetOTPVerifySerializer, PasswordResetRequestSerializer, UserSerializer
# from rest_framework.authtoken.models import Token
from django.template.loader import render_to_string
from django.utils.translation import gettext_lazy as _
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import OutstandingToken, BlacklistedToken
from django.utils.html import strip_tags

from rest_framework.permissions import AllowAny 
User = get_user_model()

def send_verification_email(user, request):
    token = RefreshToken.for_user(user).access_token
    verification_url = request.build_absolute_uri(
        reverse('verify-email') + f'?token={str(token)}'
    )
    context = {
        'user': user,
        'verification_url': verification_url
    }
    email_body = render_to_string('api/emails/verification_email.txt', context)
    send_mail(
        subject="Verify your email",
        message=email_body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )

class RegistrationAPIView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.generate_otp()
            self.send_otp_email(user,request)
            return Response({'message': 'User registered successfully. Please check your email to verify your account.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def send_otp_email(self,user,request):
        context = {
            'user':user,
            'otp':user.otp,
        }
        email_body = render_to_string('api/emails/verification_email.txt',context)
        send_mail(
            subject = 'verify your email with otp',
            message = email_body,
            from_email = settings.DEFAULT_FROM_EMAIL,
            recipient_list = [user.email],
            fail_silently = False,
        )
class VerifyEmailWithOTPAPIView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            return Response(
                {'error': 'Email and OTP are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

        if user.is_email_verified:
            return Response(
                {'error': 'Email is already verified.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if user.is_otp_valid(otp):
            user.is_email_verified = True
            user.otp = None  # Clear OTP after successful verification
            user.otp_created_at = None
            user.save()
            return Response(
                {'message': 'Email successfully verified.'},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'error': 'Invalid or expired OTP.'},
                status=status.HTTP_400_BAD_REQUEST
            )

class VerifyEmailAPIView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        token = request.GET.get('token')
        try:
            token = AccessToken(token)
            user = User.objects.get(id=token['user_id'], is_email_verified=False)
            user.is_email_verified = True
            user.save()
            return Response({'message': 'Email successfully verified.'}, status=status.HTTP_200_OK)
        except TokenError:
            return Response({'error': 'Invalid token or token expired'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'error': 'No user found.'}, status=status.HTTP_404_NOT_FOUND)

class LoginAPIView(views.APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        print(username)
        print(password)
        if not username or not password:
            return Response({"error": _("Username and password are required.")}, status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(username=username, password=password)
        if user:
            if not user.is_active:
                return Response({"error": _("Your account is disabled.")}, status=status.HTTP_403_FORBIDDEN)
            if not user.is_email_verified:
                return Response({"error": _("Email not verified. Please check your email for the OTP.")}, status=status.HTTP_401_UNAUTHORIZED)
            login(request, user)
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            secure_cookie =True
            response = JsonResponse({"message": _("Login successful.")}, status=status.HTTP_200_OK)
            response.set_cookie("access_token", access_token, httponly=True, secure=secure_cookie, samesite='strict',max_age=15 * 60 *60)
            response.set_cookie("refresh_token", refresh_token, httponly=True, secure=secure_cookie, samesite='strict',max_age=15 * 60*60)
            return response
 
        return Response({"error": _("Invalid username or password.")}, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetRequestView(views.APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response(
                    {"error": "User with this email does not exist."},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Generate and send OTP for password reset
            user.generate_reset_password_otp()  # Generate OTP
            self.send_reset_password_otp_email(user, request)  # Send OTP via email

            return Response(
                {"message": "An OTP has been sent to your email for password reset."},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_reset_password_otp_email(self, user, request):
        """
        Send an email with the password reset OTP to the user.
        """
        context = {
            'user': user,
            'otp': user.reset_password_otp,
        }
        email_body = render_to_string('api/emails/password_reset_otp_email.txt', context)
        send_mail(
            subject="Password Reset OTP",
            message=email_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )


class PasswordResetOTPVerifyView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetOTPVerifySerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            otp = serializer.validated_data["otp"]

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response(
                    {"error": "User with this email does not exist."},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Verify OTP
            if not user.is_reset_password_otp_valid(otp):
                return Response(
                    {"error": "Invalid or expired OTP."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # OTP is valid, allow the user to reset their password
            return Response(
                {"message": "OTP verified successfully. You can now reset your password."},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


from django.contrib.auth.password_validation import validate_password
class PasswordResetConfirmView(views.APIView):
    permission_classes = []

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": "Invalid data provided.", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = serializer.validated_data["user"]
        new_password = serializer.validated_data["new_password"]
        validate_password(new_password,user)

        # Update the user's password
        user.set_password(new_password)
        user.reset_password_otp = None  # Clear the OTP after successful password reset
        user.reset_password_otp_created_at = None
        user.save()

        return Response(
            {"message": "Password reset successfully."},
            status=status.HTTP_200_OK,
        )

import logging

logger = logging.getLogger(__name__)

class VerifyAuthAPIView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        access_token = request.COOKIES.get('access_token') 
        print(access_token) # Get token from cookies
        if not access_token:
            return Response({"error": "No token provided"}, status=401)

        try:
            token = AccessToken(access_token)  # Decode and validate the token
            user_id = token['user_id']
            print(user_id)
            return Response({"message": "User is authenticated", "user_id": user_id}, status=200)
        except TokenError:
            return Response({"error": "Invalid or expired token"}, status=401)


from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.permissions import BasePermission

class HasValidRefreshToken(BasePermission):
    def has_permission(self, request, view):
        print(request.data)
       
        return 'refresh_token' in request.COOKIES

class CookieTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
            return Response(
                {"error": "Refresh token not provided."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        request.data["refresh"] = refresh_token  # Inject refresh token into request data

        try:
            response = super().post(request, *args, **kwargs)
            if response.status_code == 200:
                access_token = response.data.get("access")
                # Set the new access token as an HttpOnly cookie
                response.set_cookie(
                    "access_token",
                    access_token,
                    httponly=True,
                    secure=True,  # Use secure cookies in production
                    samesite='Lax',
                    max_age=15 * 60  # 15 minutes
                )
            return response
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken, TokenBackendError

class LogoutAPIView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
            return Response(
                {"error": "No refresh token provided."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()  # Blacklist the refresh token
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Clear the access_token and refresh_token cookies
        response = Response(
            {"message": "Logout successful."},
            status=status.HTTP_200_OK
        )
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return response

class UserDetailsAPIView(views.APIView):
    """
    API endpoint to retrieve authenticated user details.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        access_token = request.COOKIES.get('access_token')  # Retrieve the token from cookies
        if not access_token:
            return Response(
                {"success": False, "error": "Access token not provided."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        try:
            # Decode and validate the access token
            token = AccessToken(access_token)
            user_id = token.get('user_id')  # Extract user ID from token payload

            # Fetch the user from the database
            user = User.objects.get(id=user_id)

            # Construct the response data
            user_data = {
                "id": user.id,
                "username": user.username,
                "email":user.email

            }

            return Response(
                {"success": True, "user": user_data},
                status=status.HTTP_200_OK
            )
        except TokenError as e:
            logger.error(f"Token error: {str(e)}", exc_info=True)
            return Response(
                {"success": False, "error": "Invalid or expired token."},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except User.DoesNotExist:
            logger.error("User not found for the provided token.")
            return Response(
                {"success": False, "error": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}", exc_info=True)
            return Response(
                {"success": False, "error": "An unexpected error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
######################################################################################################

# habit logic 

# Creating Habit Create View

class HabitCreateView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
      
        """
        Create a new habit and schedule reminders if enabled.
        """
        habit_name = request.data.get('name')
        if Habit.objects.filter(user=request.user, name=habit_name).exists():
            raise ValidationError({'name': 'A habit with this name already exists. Please choose a different name.'})
        serializer = HabitSerializer(data=request.data, context={'request': request})

        if serializer.is_valid():
            habit = serializer.save(user=request.user)
            
            if habit.reminder_toggle and habit.reminder_type == 'email':
                try:
                    self.schedule_initial_email(habit)
                    self.schedule_daily_reminders(habit)
                except Exception as e:
                    logger.error(f"Error scheduling reminders for habit {habit.id}: {e}")
                    return Response(
                        {"error": "Failed to schedule reminders. Please try again later."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def schedule_initial_email(self, habit):
        """
        Send an initial email to confirm habit reminder setup.
        """
        if habit.reminder_toggle and habit.reminder_type == 'email':
            # Convert reminder_time to a datetime.time object if it's a string
            if isinstance(habit.reminder_time, str):
                try:
                    time = datetime.strptime(habit.reminder_time, "%H:%M:%S").time()
                    habit.reminder_time = time.strftime("%H:%M:%S")
                except ValueError as e:
                    logger.error(f"Invalid reminder_time format for habit {habit.id}: {e}")
                    raise ValueError("Invalid reminder_time format. Expected 'HH:MM:SS'.")

            context = {'habit': habit}
            html_content = render_to_string('api/habits/reminder_activation_email.html', context)
            plain_message = strip_tags(html_content)

            send_mail(
                subject='Habit Reminder Setup Confirmation',
                message=plain_message,
                html_message=html_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[habit.user.email],
                fail_silently=False,
            )

    def schedule_daily_reminders(self, habit):
        """
        Schedule daily email reminders for the habit.
        """
        from django.utils.timezone import make_aware

        # Validate start_date and end_date
        if habit.start_date is None:
            raise ValueError("start_date cannot be None.")
        
        # Use today's date if end_date is not provided
        end_date = habit.end_date if habit.end_date else (timezone.now().date() + timedelta(days=30))

        # Ensure start_date is not in the past
        start_date = max(habit.start_date, timezone.now().date())

        # Schedule reminders for each day from start_date to end_date
        for single_date in (start_date + timedelta(n) for n in range((end_date - start_date).days + 1)):
            try:
                # Convert reminder_time to a datetime.time object
                time = datetime.strptime(habit.reminder_time, "%H:%M:%S").time()
                eta = make_aware(datetime.combine(single_date, time))

                # Schedule the Celery task
                send_email_reminder.apply_async((habit.id,), eta=eta)
                logger.info(f"Scheduled reminder for habit {habit.id} at {eta}")
            except Exception as e:
                logger.error(f"Error scheduling reminder for habit {habit.id} on {single_date}: {e}")
                raise

class HabitListView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        habits = Habit.objects.filter(user=request.user)
        print(habits)
        serializer = HabitDetailSerializer(habits, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)    
    


# Fetchig Habit Details 
class HabitDetailView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, format=None):
        habit = Habit.objects.filter(pk=pk, user=request.user).first()
        if not habit:
            return Response({'error': 'Habit not found.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = HabitDetailSerializer(habit)
        return Response(serializer.data)

    def patch(self, request, pk, format=None):
        habit = get_object_or_404(Habit, pk=pk, user=request.user)
        serializer = HabitSerializer(habit, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            # Re-schedule reminders if reminder settings are modified
            if 'reminder_toggle' in request.data or 'reminder_time' in request.data:
                habit.reschedule_reminders()  # You'd need to implement this method in your model
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class HabitCompletionToggleView(views.APIView):
    """
    View to toggle a habit's completion status for the day.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, pk, *args, **kwargs):
        # Fetch the habit for the logged-in user
        try:
            habit = Habit.objects.get(pk=pk, user=request.user)
        except Habit.DoesNotExist:
            return Response({"error": "Habit not found or not accessible."}, status=status.HTTP_404_NOT_FOUND)

        # Get the completion status from the request data
        completed = request.data.get("completed", True)

        # Get or create a log for today
        today = date.today()
        # print(today)
        log, created = HabitLog.objects.get_or_create(
            habit=habit,
            date=today, 
            defaults={
                'completed': completed,
                'notes': request.data.get('notes', ''),
                'mood': request.data.get('mood', '')
            }
        )
        # If the log already exists, update it if needed
        if not created and log.completed != completed:
            log.completed = completed
            log.notes = request.data.get('notes', log.notes)
            log.mood = request.data.get('mood', log.mood)
            log.save()  
       
        # Update the habit's completion status
        habit.is_completed_today =True
        habit.save()
        # Calculate the current streak or reset it
        if completed:
            current_streak = habit.calculate_streak()
        else:
            habit.is_completed_today = True
            print("HI")
            habit.reset_streak()

            current_streak = 0
        
        goal_acheived = False
        if habit.is_achieved:
            goal_acheived = True
        # Prepare serialized data
        habit_serializer = HabitDetailSerializer(habit)
        log_serializer = HabitLogSerializer(log)
       

        return Response({
            "message": f"Habit marked as {'completed' if completed else 'not completed'} for today.",
            "current_streak": habit.curr_streak,
            "max_streak": habit.max_streak,
            "is_completed_today":habit.is_completed_today,
            "is_achieved":goal_acheived,
            "streak_updated_at":habit.streak_updated_at,
            "habit": habit_serializer.data,
            "log": log_serializer.data
        }, status=status.HTTP_200_OK)
    
# Habit deletion 
class HabitDeleteView(views.APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk, format=None):
        try:
            habit = Habit.objects.get(pk=pk, user=request.user)  # Ensure the habit belongs to the logged-in user
        except Habit.DoesNotExist:
            return Response({'error': 'Habit not found or not accessible.'}, status=status.HTTP_404_NOT_FOUND)

        habit.delete()
        return Response({'message': 'Habit deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
    
class HabitLogView(views.APIView):
    """
    View to fetch all logs for a habit.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request,pk):
        """
        Fetch all logs for a habit.
        
        """
        print(request)
        try:
            habit = get_object_or_404(Habit, id=pk)
            date = request.query_params.get('date')
            logs = HabitLog.objects.filter(habit_id=pk,date = date)
            for i in logs:
                print(i)

        except Habit.DoesNotExist:
            return Response({"error": "Habit not found"}, status=status.HTTP_404_NOT_FOUND)
        
        return Response({
               "habit": HabitSerializer(habit).data,
               "logs": HabitLogSerializer(logs, many=True).data,
             })