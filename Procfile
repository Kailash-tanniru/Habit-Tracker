web: gunicorn auth_project.wsgi --log-file -
worker: celery -A auth_project worker --loglevel=info