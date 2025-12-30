"""API routes for notifications."""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user
from app.services.notification_service import NotificationService

bp = Blueprint('notifications', __name__)
notification_service = NotificationService()


@bp.route('/notifications')
@login_required
def notifications_page():
    """Display notifications page."""
    return render_template('notifications.html')


@bp.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    """
    Get user's notifications with pagination
    ---
    tags:
      - Notifications
    parameters:
      - in: query
        name: limit
        type: integer
        default: 20
      - in: query
        name: unread_only
        type: boolean
        default: false
    responses:
      200:
        description: List of notifications
    """
    limit = request.args.get('limit', 20, type=int)
    unread_only = request.args.get('unread_only', 'false').lower() == 'true'
    
    notifications = notification_service.get_user_notifications(
        current_user.id,
        limit=limit,
        unread_only=unread_only
    )
    
    return jsonify({
        'notifications': notifications,
        'unread_count': notification_service.get_unread_count(current_user.id)
    })


@bp.route('/api/notifications/unread-count', methods=['GET'])
@login_required
def get_unread_count():
    """
    Get count of unread notifications
    ---
    tags:
      - Notifications
    responses:
      200:
        description: Unread notification count
    """
    count = notification_service.get_unread_count(current_user.id)
    return jsonify({'unread_count': count})


@bp.route('/api/notifications/<notification_id>/read', methods=['POST'])
@login_required
def mark_as_read(notification_id):
    """
    Mark notification as read
    ---
    tags:
      - Notifications
    parameters:
      - in: path
        name: notification_id
        type: string
        required: true
    responses:
      200:
        description: Notification marked as read
    """
    success = notification_service.mark_as_read(notification_id, current_user.id)
    return jsonify({'success': success})


@bp.route('/api/notifications/read-all', methods=['POST'])
@login_required
def mark_all_as_read():
    """
    Mark all unread notifications as read
    ---
    tags:
      - Notifications
    responses:
      200:
        description: All notifications marked as read
    """
    count = notification_service.mark_all_as_read(current_user.id)
    return jsonify({'marked_count': count})


@bp.route('/api/notifications/<notification_id>', methods=['DELETE'])
@login_required
def delete_notification(notification_id):
    """
    Delete a notification
    ---
    tags:
      - Notifications
    parameters:
      - in: path
        name: notification_id
        type: string
        required: true
    responses:
      200:
        description: Notification deleted
    """
    success = notification_service.delete_notification(notification_id, current_user.id)
    return jsonify({'success': success})
