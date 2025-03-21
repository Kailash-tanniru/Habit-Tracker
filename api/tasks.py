from datetime import timedelta
from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from .models import CustomUser, Habit
import logging

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3)
def send_email_reminder(self, habit_id):
    """
    Celery task to send email reminders for habits.
    """
    try:
        habit = Habit.objects.get(id=habit_id)
        
        # Check if reminders are enabled and the habit is still active
        if not habit.reminder_toggle or habit.end_date < timezone.now().date():
            return

        # Send the email reminder
        send_mail(
            subject=f'Reminder for Your Habit: {habit.name}',
            message=f"Remember to maintain your habit: {habit.name}!",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[habit.user.email],
            fail_silently=False,
        )
    except Habit.DoesNotExist:
        logger.warning(f"Habit with ID {habit_id} no longer exists. Skipping reminder.")
    except Exception as e:
        logger.error(f"Error sending reminder for habit ID {habit_id}: {e}")
        raise self.retry(exc=e, countdown=60)  # Retry after 60 seconds
    


from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from .models import Habit
import logging

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3)
def send_email_reminder(self, habit_id):
    """
    Celery task to send email reminders for habits.
    """
    try:
        habit = Habit.objects.get(id=habit_id)
        
        # Check if reminders are enabled and the habit is still active
        if not habit.reminder_toggle or habit.end_date < timezone.now().date():
            return

        # Send the email reminder
        send_mail(
            subject=f'Reminder for Your Habit: {habit.name}',
            message=f"Remember to maintain your habit: {habit.name}!",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[habit.user.email],
            fail_silently=False,
        )
    except Habit.DoesNotExist:
        logger.warning(f"Habit with ID {habit_id} no longer exists. Skipping reminder.")
    except Exception as e:
        logger.error(f"Error sending reminder for habit ID {habit_id}: {e}")
        raise self.retry(exc=e, countdown=60)  # Retry after 60 seconds

@shared_task
def reset_inactive_streaks():
    """
    Celery task to reset streaks for habits where no action was logged yesterday.
    """
    from datetime import date, timedelta
    from .models import Habit

    today = date.today()
    yesterday = today - timedelta(days=1)
    Habit.objects.update(is_completed_today = False)


    habits = Habit.objects.all()
    for habit in habits:
        habit.noaction_streakReset()
    logger.info("Daily habit reset and streak monitoring completed.")


@shared_task
def delete_expired_otps():
    """
    Delete OTPs that have expired and were not used.
    """
    # Calculate the expiration time (e.g., 5 minutes ago)
    expiration_time = timezone.now() - timedelta(minutes=5)

    # Delete expired OTPs
    CustomUser.objects.filter(
        otp_created_at__lte=expiration_time
    ).update(otp=None, otp_created_at=None)

    # Delete expired password reset OTPs
    CustomUser.objects.filter(
        reset_password_otp_created_at__lte=expiration_time
    ).update(reset_password_otp=None, reset_password_otp_created_at=None)

    print("Expired OTPs deleted successfully.")