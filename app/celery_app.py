"""Celery application factory."""

import os
from celery import Celery

# Create Celery instance
celery_app = Celery(
    'elaslip',
    broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/1'),
    backend=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/1')
)

# Configure Celery from app config
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

# Auto-discover tasks from all registered apps
if __name__ == '__main__':
    celery_app.start()
