from django.urls import path
from .views import (
    CookieTokenRefreshView,
    HabitCompletionToggleView,
    HabitCreateView,
    HabitDeleteView,
    HabitDetailView,
    HabitListView,
    HabitLogView,
    LoginAPIView,
    LogoutAPIView,

    RegistrationAPIView,
    UserDetailsAPIView,
    VerifyEmailAPIView,


    PasswordResetRequestView,
    PasswordResetOTPVerifyView,
    PasswordResetConfirmView,
    VerifyAuthAPIView,
    VerifyEmailWithOTPAPIView,  # For authentication verification
)
# from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    #User login Management
    
    # Authentication
    path("api/login/", LoginAPIView.as_view(), name="api_login"),
    path("api/logout/", LogoutAPIView.as_view(), name="api_logout"),
    # Registration and Email Verification
    path("api/register/", RegistrationAPIView.as_view(), name="api_register"),
    path("api/verify-email/", VerifyEmailAPIView.as_view(), name="verify-email"),
     path('api/verify-email-with-otp/', VerifyEmailWithOTPAPIView.as_view(), name='verify-email-with-otp'),
    # Password Reset
    # path("api/password_reset/", PasswordResetRequestView.as_view(), name="password_reset_request"),
    # path(
    #     "api/password_reset_confirm/<uidb64>/<token>/",
    #     PasswordResetConfirmView.as_view(),
    #     name="password_reset_confirm",
    # ),

    path("api/password-reset-request/", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("api/password-reset-verify-otp/", PasswordResetOTPVerifyView.as_view(), name="password-reset-verify-otp"),
    path("api/password-reset-confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),

    # Token Management
    path("api/token/refresh/", CookieTokenRefreshView.as_view(), name="token_refresh"),
    # Verify Authentication
    path("api/auth/verify/", VerifyAuthAPIView.as_view(), name="verify_auth"),
    path("api/user/details/", UserDetailsAPIView.as_view(), name="user-details"),

    # HabitTrack Endpoints
    # Habit Management
    path("api/habits/create/", HabitCreateView.as_view(), name="create_habit"),
    path("api/habits/", HabitListView.as_view(), name="view_habit"),
    path('api/habits/<int:pk>/', HabitDetailView.as_view(), name='habit-detail'),
    path("api/habits/<int:pk>/toggle-completion/", HabitCompletionToggleView.as_view(), name="toggle_habit_completion"),
    path("api/habits/<int:pk>/delete/", HabitDeleteView.as_view(), name="delete_habit"),
    path("api/habits/<int:pk>/logs/", HabitLogView.as_view(), name="habit_logs"),
   
]
