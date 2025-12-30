/**
 * Notification System
 * Handles fetching, displaying, and managing notifications via sidebar
 */

class NotificationManager {
    constructor() {
        this.updateInterval = 10000; // 10 seconds
        this.pollTimer = null;
        this.sidebarOpen = false;
        this.init();
    }

    init() {
        this.setupNotificationUI();
        this.startPolling();
        this.loadNotifications();
    }

    setupNotificationUI() {
        // Setup notification nav link click handler
        const navLink = document.getElementById('notification-nav-link');
        if (navLink) {
            navLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggleSidebar();
            });
        }

        // Setup sidebar close button
        const closeBtn = document.getElementById('sidebar-close-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.closeSidebar());
        }

        // Setup overlay click to close
        const overlay = document.getElementById('notifications-sidebar-overlay');
        if (overlay) {
            overlay.addEventListener('click', () => this.closeSidebar());
        }

        // Setup mark all read button
        const markAllBtn = document.getElementById('mark-all-read-sidebar');
        if (markAllBtn) {
            markAllBtn.addEventListener('click', () => this.markAllAsRead());
        }

    }

    toggleSidebar() {
        if (this.sidebarOpen) {
            this.closeSidebar();
        } else {
            this.openSidebar();
        }
    }

    openSidebar() {
        const sidebar = document.getElementById('notifications-sidebar');
        const overlay = document.getElementById('notifications-sidebar-overlay');
        
        if (sidebar && overlay) {
            sidebar.classList.add('show');
            overlay.classList.add('show');
            this.sidebarOpen = true;
            document.body.style.overflow = 'hidden';
        }
    }

    closeSidebar() {
        const sidebar = document.getElementById('notifications-sidebar');
        const overlay = document.getElementById('notifications-sidebar-overlay');
        
        if (sidebar && overlay) {
            sidebar.classList.remove('show');
            overlay.classList.remove('show');
            this.sidebarOpen = false;
            document.body.style.overflow = '';
        }
    }

    startPolling() {
        if (this.pollTimer) clearInterval(this.pollTimer);
        
        this.pollTimer = setInterval(() => {
            this.loadNotifications();
        }, this.updateInterval);
    }

    stopPolling() {
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
            this.pollTimer = null;
        }
    }

    loadNotifications() {
        
        fetch('/api/notifications', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            this.updateNotifications(data);
        })
        .catch(error => {
        });
    }

    updateNotifications(data) {
        // Update badge count
        const count = data.unread_count || 0;
        this.updateBadge(count);

        // Update notifications list
        const listContainer = document.getElementById('notifications-list-sidebar');
        if (!listContainer) {
            console.error('Notifications list container not found');
            return;
        }

        const notifications = data.notifications || [];

        if (notifications.length === 0) {
            listContainer.innerHTML = `
                <div class="notifications-empty">
                    <i class="bi bi-bell-slash"></i>
                    <p>No notifications</p>
                </div>
            `;
            return;
        }

        // Build notifications HTML
        let html = '';
        notifications.forEach(notif => {
            const icon = this.getNotificationIcon(notif.level);
            const time = this.formatTime(notif.created_at);
            const readClass = notif.read ? 'notification-read' : 'notification-unread';
            const levelClass = `notification-${notif.level}`;
            
            html += `
                <div class="notification-item ${readClass} ${levelClass}" data-id="${notif.id}">
                    <div class="notification-icon">
                        ${icon}
                    </div>
                    <div class="notification-content">
                        <div class="notification-title">${this.escapeHtml(notif.title)}</div>
                        <div class="notification-message">${this.escapeHtml(notif.message)}</div>
                        <div class="notification-time">${time}</div>
                    </div>
                    <div class="notification-actions">
                        <button class="notification-action-btn" title="Mark as read" onclick="notificationManager.toggleRead('${notif.id}', ${notif.read})">
                            <i class="bi ${notif.read ? 'bi-envelope-open' : 'bi-envelope'}"></i>
                        </button>
                        <button class="notification-action-btn" title="Delete" onclick="notificationManager.deleteNotification('${notif.id}')">
                            <i class="bi bi-trash"></i>
                        </button>
                    </div>
                </div>
            `;
        });

        listContainer.innerHTML = html;
    }

    getNotificationIcon(level) {
        const icons = {
            'success': '<i class="bi bi-check-circle-fill text-success"></i>',
            'info': '<i class="bi bi-info-circle-fill text-info"></i>',
            'warning': '<i class="bi bi-exclamation-triangle-fill text-warning"></i>',
            'error': '<i class="bi bi-exclamation-circle-fill text-danger"></i>',
            'danger': '<i class="bi bi-exclamation-circle-fill text-danger"></i>'
        };
        return icons[level] || '<i class="bi bi-bell-fill"></i>';
    }

    updateBadge(count) {
        const badge = document.getElementById('notification-nav-badge');
        const badgeCount = document.getElementById('notification-nav-count');
        
        if (badge && badgeCount) {
            if (count > 0) {
                badgeCount.textContent = count > 99 ? '99+' : count;
                badge.style.display = 'inline-block';
            } else {
                badge.style.display = 'none';
            }
        }
    }

    toggleRead(notificationId, isRead) {
        const newReadState = !isRead;
        
        fetch(`/api/notifications/${notificationId}/read`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ read: newReadState })
        })
        .then(response => {
            if (!response.ok) throw new Error('Failed to update notification');
            this.loadNotifications();
        })
        .catch(error => {
            console.error('Error updating notification:', error);
        });
    }

    deleteNotification(notificationId) {
        if (!confirm('Delete this notification?')) return;
        
        fetch(`/api/notifications/${notificationId}`, {
            method: 'DELETE',
            credentials: 'include'
        })
        .then(response => {
            if (!response.ok) throw new Error('Failed to delete notification');
            this.loadNotifications();
        })
        .catch(error => {
            console.error('Error deleting notification:', error);
        });
    }

    markAllAsRead() {
        fetch('/api/notifications/read-all', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include'
        })
        .then(response => {
            if (!response.ok) throw new Error('Failed to mark all as read');
            this.loadNotifications();
        })
        .catch(error => {
            console.error('Error marking all as read:', error);
        });
    }

    formatTime(isoString) {
        if (!isoString) return '';
        
        const date = new Date(isoString);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        if (diffDays < 7) return `${diffDays}d ago`;
        
        return date.toLocaleDateString();
    }

    escapeHtml(text) {
        if (!text) return '';
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return String(text).replace(/[&<>"']/g, m => map[m]);
    }
}

// Initialize notification manager when DOM is ready
let notificationManager;

document.addEventListener('DOMContentLoaded', () => {
    notificationManager = new NotificationManager();
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (notificationManager) {
        notificationManager.stopPolling();
    }
});
