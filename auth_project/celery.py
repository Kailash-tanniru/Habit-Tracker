from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_project.settings')

# Create the Celery app
app = Celery('auth_project')

# Load task modules from all registered Django apps
app.config_from_object('django.conf:settings', namespace='CELERY')

# Configure periodic tasks
app.conf.beat_schedule = {
    'delete-expired-otps-every-hour': {
        'task': 'api.tasks.delete_expired_otps',
        'schedule': crontab(minute=0, hour='*'),  # Run every hour
    },
    'reset-inactive-streaks-daily': {
        'task': 'api.tasks.reset_inactive_streaks',
        'schedule': crontab(minute=0, hour=0),  # Run daily at midnight
    },
}

# Autodiscover tasks
app.autodiscover_tasks()