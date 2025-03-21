from venv import logger
from celery import shared_task
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.core.exceptions import ValidationError

from datetime import date, datetime, timedelta, timezone

from django.dispatch import receiver



from django.db.models.signals import post_save
# Custom User Model
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta
import random

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True, blank=False)
    is_email_verified = models.BooleanField(default=False)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    otp = models.CharField(max_length=6, blank=True, null=True)  # Store OTP
    otp_created_at = models.DateTimeField(blank=True, null=True)  # OTP creation time
    reset_password_otp = models.CharField(max_length=6, blank=True, null=True)  # Password reset OTP
    reset_password_otp_created_at = models.DateTimeField(blank=True, null=True)  # Password reset OTP creation tim
    def generate_reset_password_otp(self):

      
        self.reset_password_otp = str(random.randint(100000, 999999))  # 6-digit OTP
        self.reset_password_otp_created_at = timezone.now()
        self.save()

    def is_reset_password_otp_valid(self, otp):
        """
        Check if the provided password reset OTP is valid and not expired.
        """
        if self.reset_password_otp == otp and self.reset_password_otp_created_at:
            expiration_time = self.reset_password_otp_created_at + timedelta(minutes=5)  # OTP expires in 5 minutes
            return timezone.now() <= expiration_time
        return False

    def generate_otp(self):
        """
        Generate a 6-digit OTP and set its expiration time (e.g., 5 minutes).
        """
 
        self.otp = str(random.randint(100000, 999999))  # 6-digit OTP
        self.otp_created_at = timezone.now()
        self.save()

    def is_otp_valid(self, otp):
        """
        Check if the provided OTP is valid and not expired.
        """
        if self.otp == otp and self.otp_created_at:
            expiration_time = self.otp_created_at + timedelta(minutes=5)  # OTP expires in 5 minutes
            return timezone.now() <= expiration_time
        return False

# Activity Log Model
class ActivityLog(models.Model):
    """
    Logs user activity, including actions and IP addresses.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.user.username} - {self.action} at {self.timestamp}'


# Habit Model
class Habit(models.Model):
    """
    Stores details of each habit, including scheduling options, reminders, and rewards.
    """
    REMINDER_CHOICES = [
        ('none', 'None'),
        ('email', 'Email'),
        ('whatsapp', 'WhatsApp'),
    ]

    FREQUENCY_CHOICES = [
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('custom', 'Custom'),  # Custom scheduling logic (e.g., certain days of the week)
    ]

    MOOD_CHOICES = [
        ('happy', 'Happy'),
        ('sad', 'Sad'),
        ('neutral', 'Neutral'),
        ('stressed', 'Stressed'),
        ('energized', 'Energized'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='habits'
    )
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    start_date = models.DateField()
    end_date = models.DateField(blank=True, null=True)
    reminder_toggle = models.BooleanField(default=False)
    reminder_type = models.CharField(
        max_length=20,
        choices=REMINDER_CHOICES,
        default='none'
    )
    reminder_time = models.TimeField(default='18:19:00')
    reward = models.CharField(max_length=200, blank=True, null=True)
    curr_streak = models.IntegerField(default=0, verbose_name="Current Streak")
    max_streak = models.IntegerField(default=0, verbose_name="Maximum Streak")
    is_completed_today = models.BooleanField(default=False)
    
    streak_updated_at = models.DateField(auto_now=True)  # Track when streak was last updated
    timezone = models.CharField(max_length=50, default='UTC')  # For handling reminders in user's timezone
    is_important = models.BooleanField(default=False)  # Star icon for important habits
    is_active = models.BooleanField(default=True)      # Bulb icon for active streak
    frequency = models.CharField(
        max_length=20,
        choices=FREQUENCY_CHOICES,
        default='daily'
    )
    is_achieved = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.name} (User: {self.user.username})"

    def clean(self):
        """
        Validate that end_date is not before start_date.
        """
        if self.end_date and self.end_date < self.start_date:
            raise ValidationError("End date cannot be before start date.")

    @property
    def current_streak(self):
        """
        Calculate and return the current streak for the habit.
        """
        return self.calculate_streak()

    @property
    def remaining_days(self):
        """
        Calculate the remaining days for the habit streak to be completed.
        """
        if self.end_date:
            return (self.end_date - date.today()).days
        return None

    def update_streak(self, new_streak):
        """
        Update the maximum streak if the new streak is greater.
        """
        if new_streak > self.max_streak:
            self.max_streak = new_streak
            self.save()

    def reset_streak(self):
        """
        Reset the streak and delete all logs.
        """
       
        self.curr_streak  = 0
        self.streak_updated_at = date.today()
          # Resets all logs, consider preserving history if needed
        self.save()

    def mark_completed_today(self):
        """
        Mark the habit as completed for today and update the streak.
        """
        if not self.is_completed_today:
            self.is_completed_today = True
            self.logs.create(date=date.today(), completed=True)
            self.streak_updated_at = date.today()
            self.save()
            self.calculate_streak()
   
    def check_if_acheived(self):
        if self.end_date:
            total_days= (self.end_date - self.start_date).days + 1
            if self.curr_streak >= total_days:
                self.is_achieved = True
            else:
                self.is_achieved = False
            self.save()
        return self.is_achieved

    def calculate_streak(self):
        """
        Calculate the current streak based on completed logs.
        """
        logs = self.logs.filter(completed=True).order_by('date')
  
        current_streak =0
        last_date = None


        for log in logs:
            if last_date is None or (log.date - last_date).days == 1:
                current_streak += 1
                last_date = log.date
            else:
                # If there's a gap in the dates, reset the streak
                current_streak = 1
            last_date = log.date

        print(current_streak)
        print(last_date)
       
        self.curr_streak  = current_streak
        self.streak_updated_at = last_date

        # Update max streak if needed
        self.update_streak(current_streak)
        self.check_if_acheived()

        return current_streak

    

    def noaction_streakReset(self):
        today = date.today()
        yesterday = today - timedelta(days=1)
        has_action_yesterday = self.logs.filter(date = yesterday,completed = True).exists()
        if not has_action_yesterday:
            self.curr_streak =0
            self.streak_updated_at = today
            self.save()


from django.conf import settings


from django.utils import timezone



# @shared_task
# def reset_inactive_streaks():
#     habits = Habit.objects.all()
#     for habit in habits:
#         habit.noaction_streakReset()


# @shared_task(bind=True, max_retries=3)
# def send_email_reminder(self, habit_id):
#     try:
#         habit = Habit.objects.get(id=habit_id)
        
#         if not habit.reminder_toggle or habit.end_date < timezone.now().date():
#             return

#         send_mail(
#             subject=f'Reminder for Your Habit: {habit.name}',
#             message=f"Remember to maintain your habit: {habit.name}!",
#             from_email=settings.DEFAULT_FROM_EMAIL,
#             recipient_list=[habit.user.email],
#             fail_silently=False,
#         )
#     except ObjectDoesNotExist:
#         logger.warning(f"Habit with ID {habit_id} no longer exists. Skipping reminder.")
#     except Exception as e:
#         logger.error(f"Error sending reminder for habit ID {habit_id}: {e}")
#         raise self.retry(exc=e, countdown=60)  # Retry after 60 seconds




# @receiver(post_save, sender=Habit)
# def schedule_habit_reminders(sender, instance, created, **kwargs):
#     if created and instance.reminder_toggle and instance.reminder_type == 'email':
#         current_date = timezone.localtime().date()
#         if instance.start_date > current_date:
#             # Schedule starting from start_date if it's in the future
#             start_date = instance.start_date
#         else:
#             # Or from today if the start date is today or in the past
#             start_date = current_date

#         for single_date in (start_date + timedelta(n) for n in range((instance.end_date - start_date).days + 1)):
#             eta = timezone.make_aware(datetime.combine(single_date, instance.reminder_time))
#             send_email_reminder.apply_async((instance.id,), eta=eta)

# Habit Log Model
class HabitLog(models.Model):
    """
    Logs the status of habit completion for a specific date.
    """
    habit = models.ForeignKey(
        Habit,
        on_delete=models.CASCADE,
        related_name='logs'
    )
    date = models.DateField()
    completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)  # Track when the log was created
    notes = models.TextField(blank=True, null=True)       # Allow users to add notes
    mood = models.CharField(max_length=20, choices=Habit.MOOD_CHOICES, blank=True, null=True)  # Track user mood

    class Meta:
          # Ensure only one log per habit per dat
        unique_together = ('habit', 'date')
        ordering = ['-date']  # Order logs by date in descending order

    def __str__(self):
        status = "Completed" if self.completed else "Missed"
        return f"{self.habit.name} on {self.date} - {status} - {self.notes} - {self.mood}"