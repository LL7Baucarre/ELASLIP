"""Notification service for user notifications."""

from datetime import datetime
import uuid
from app.services.elasticsearch_service import ElasticsearchService
from flask_login import current_user


class NotificationService:
    """Service for managing user notifications."""
    
    # Notification types
    REPORT_COMPLETED = 'report_completed'
    REPORT_FAILED = 'report_failed'
    SUBMISSION_RECEIVED = 'submission_received'
    SUBMISSION_PROCESSED = 'submission_processed'
    IOC_EXPIRING = 'ioc_expiring'
    IOC_EXPIRED = 'ioc_expired'
    
    # Notification levels
    INFO = 'info'
    SUCCESS = 'success'
    WARNING = 'warning'
    ERROR = 'error'
    
    def __init__(self):
        self.es = ElasticsearchService()
        self.index = 'elaslip_notifications'
    
    def create_notification(self, user_id, notification_type, title, message, level=INFO, 
                           related_type=None, related_id=None, data=None):
        """
        Create a new notification for a user.
        
        Args:
            user_id: Target user ID
            notification_type: Type of notification (REPORT_COMPLETED, etc.)
            title: Short notification title
            message: Full notification message
            level: Notification level (info, success, warning, error)
            related_type: Type of related entity (report, submission, ioc)
            related_id: ID of related entity
            data: Additional data dictionary
        
        Returns:
            Notification document
        """
        notification_id = str(uuid.uuid4())
        
        notification = {
            'id': notification_id,
            'user_id': user_id,
            'type': notification_type,
            'title': title,
            'message': message,
            'level': level,
            'related_type': related_type,
            'related_id': related_id,
            'data': data or {},
            'read': False,
            'created_at': datetime.utcnow().isoformat(),
            'read_at': None,
            'action_url': None,
        }
        
        # Set action URL based on notification type
        if related_type and related_id:
            if related_type == 'report':
                notification['action_url'] = f'/reports/loading?task_id={related_id}'
            elif related_type == 'submission':
                notification['action_url'] = f'/submissions'
            elif related_type == 'ioc':
                notification['action_url'] = f'/iocs/{related_id}'
        
        # Index in Elasticsearch
        try:
            self.es.index(self.index, notification_id, notification)
            return notification
        except Exception as e:
            print(f"Error creating notification: {e}")
            return None
    
    def get_user_notifications(self, user_id, limit=50, unread_only=False):
        """
        Get notifications for a user.
        
        Args:
            user_id: User ID
            limit: Maximum notifications to return
            unread_only: Only return unread notifications
        
        Returns:
            List of notification documents
        """
        try:
            query = {
                'query': {
                    'bool': {
                        'must': [
                            {'term': {'user_id': user_id}}
                        ]
                    }
                },
                'sort': [{'created_at': {'order': 'desc'}}],
                'size': limit
            }
            
            if unread_only:
                query['query']['bool']['must'].append({'term': {'read': False}})
            
            result = self.es.search(self.index, query)
            notifications = []
            
            for hit in result.get('hits', {}).get('hits', []):
                doc = hit['_source']
                doc['_id'] = hit['_id']
                notifications.append(doc)
            
            return notifications
        except Exception as e:
            print(f"Error fetching notifications: {e}")
            return []
    
    def get_unread_count(self, user_id):
        """Get count of unread notifications."""
        try:
            query = {
                'query': {
                    'bool': {
                        'must': [
                            {'term': {'user_id': user_id}},
                            {'term': {'read': False}}
                        ]
                    }
                },
                'size': 0
            }
            
            result = self.es.search(self.index, query)
            return result.get('hits', {}).get('total', {}).get('value', 0)
        except Exception as e:
            print(f"Error counting unread notifications: {e}")
            return 0
    
    def mark_as_read(self, notification_id, user_id):
        """Mark a notification as read."""
        try:
            # Get the notification first to verify ownership
            response = self.es.get(self.index, notification_id)
            if not response or not response.get('found'):
                return False
            
            notification = response.get('_source', {})
            if notification.get('user_id') != user_id:
                return False  # Not owner
            
            # Update notification
            notification['read'] = True
            notification['read_at'] = datetime.utcnow().isoformat()
            
            self.es.index(self.index, notification_id, notification)
            return True
        except Exception as e:
            print(f"Error marking notification as read: {e}")
            return False
    
    def mark_all_as_read(self, user_id):
        """Mark all unread notifications as read for a user."""
        try:
            # Get all unread notifications
            unread = self.get_user_notifications(user_id, limit=1000, unread_only=True)
            
            success_count = 0
            for notification in unread:
                if self.mark_as_read(notification['_id'], user_id):
                    success_count += 1
            
            return success_count
        except Exception as e:
            print(f"Error marking all notifications as read: {e}")
            return 0
    
    def delete_notification(self, notification_id, user_id):
        """Delete a notification (verify ownership)."""
        try:
            # Get the notification first to verify ownership
            response = self.es.get(self.index, notification_id)
            if not response or not response.get('found'):
                return False
            
            notification = response.get('_source', {})
            if notification.get('user_id') != user_id:
                return False  # Not owner
            
            self.es.delete(self.index, notification_id)
            return True
        except Exception as e:
            print(f"Error deleting notification: {e}")
            return False
    
    def notify_report_completed(self, user_id, report_type, entity_name, task_id):
        """Notify user that a report has been completed."""
        return self.create_notification(
            user_id=user_id,
            notification_type=self.REPORT_COMPLETED,
            title=f'{report_type.title()} Report Ready',
            message=f'Your {report_type} report for "{entity_name}" has been generated successfully.',
            level=self.SUCCESS,
            related_type='report',
            related_id=task_id,
            data={'report_type': report_type, 'entity_name': entity_name}
        )
    
    def notify_report_failed(self, user_id, report_type, entity_name, error_message):
        """Notify user that a report generation failed."""
        return self.create_notification(
            user_id=user_id,
            notification_type=self.REPORT_FAILED,
            title=f'{report_type.title()} Report Failed',
            message=f'Report generation failed: {error_message}',
            level=self.ERROR,
            related_type='report',
            data={'report_type': report_type, 'entity_name': entity_name, 'error': error_message}
        )
    
    def notify_submission_received(self, admin_user_id, submission_id, source):
        """Notify admin that a new submission has been received."""
        return self.create_notification(
            user_id=admin_user_id,
            notification_type=self.SUBMISSION_RECEIVED,
            title='New Submission Received',
            message=f'A new submission has been received from {source}.',
            level=self.INFO,
            related_type='submission',
            related_id=submission_id,
            data={'source': source}
        )
    
    def notify_submission_processed(self, user_id, ioc_count):
        """Notify user that their submission has been processed."""
        return self.create_notification(
            user_id=user_id,
            notification_type=self.SUBMISSION_PROCESSED,
            title='Submission Processed',
            message=f'Your submission has been processed successfully. {ioc_count} IOCs have been created.',
            level=self.SUCCESS,
            related_type='submission',
            data={'ioc_count': ioc_count}
        )
    
    def notify_ioc_expiring(self, user_id, ioc_value):
        """Notify user that an IOC is about to expire."""
        return self.create_notification(
            user_id=user_id,
            notification_type=self.IOC_EXPIRING,
            title='IOC Expiring Soon',
            message=f'The IOC "{ioc_value}" will expire in the next 24 hours.',
            level=self.WARNING,
            related_type='ioc',
            data={'ioc_value': ioc_value}
        )
    
    def notify_ioc_expired(self, user_id, ioc_value):
        """Notify user that an IOC has expired."""
        return self.create_notification(
            user_id=user_id,
            notification_type=self.IOC_EXPIRED,
            title='IOC Expired',
            message=f'The IOC "{ioc_value}" has reached its expiration date.',
            level=self.WARNING,
            related_type='ioc',
            data={'ioc_value': ioc_value}
        )
