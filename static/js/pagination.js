/**
 * Centralized pagination utilities for all paginated lists
 */

/**
 * Render pagination controls
 * @param {number} total - Total number of items
 * @param {number} page - Current page number
 * @param {number} perPage - Items per page
 * @param {string} elementId - ID of pagination list element (default: 'paginationList')
 * @param {function} callback - Callback function when page changes (default: goToPage)
 */
function renderPagination(total, page, perPage, elementId = 'paginationList', callback = 'goToPage') {
    const totalPages = Math.ceil(total / perPage);
    const start = (page - 1) * perPage + 1;
    const end = Math.min(page * perPage, total);

    const paginationInfo = document.getElementById('paginationInfo');
    if (paginationInfo) {
        paginationInfo.textContent = total > 0 ? `Showing ${start}-${end} of ${total}` : 'No results';
    }

    const paginationList = document.getElementById(elementId);
    if (!paginationList) return;

    if (totalPages <= 1) {
        paginationList.innerHTML = '';
        return;
    }

    let html = `<li class="page-item ${page === 1 ? 'disabled' : ''}">
        <a class="page-link" href="#" onclick="if(window.${callback}) window.${callback}(${page - 1}); return false;">&laquo;</a>
    </li>`;

    for (let i = 1; i <= Math.min(totalPages, 5); i++) {
        html += `<li class="page-item ${page === i ? 'active' : ''}">
            <a class="page-link" href="#" onclick="if(window.${callback}) window.${callback}(${i}); return false;">${i}</a>
        </li>`;
    }

    html += `<li class="page-item ${page === totalPages ? 'disabled' : ''}">
        <a class="page-link" href="#" onclick="if(window.${callback}) window.${callback}(${page + 1}); return false;">&raquo;</a>
    </li>`;

    paginationList.innerHTML = html;
}

/**
 * Format date to readable string
 * @param {string} dateStr - ISO date string
 * @returns {string} Formatted date
 */
function formatDate(dateStr) {
    if (!dateStr) return '-';
    try {
        return new Date(dateStr).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    } catch (e) {
        return '-';
    }
}

/**
 * Format datetime to readable string
 * @param {string} dateStr - ISO datetime string
 * @returns {string} Formatted datetime
 */
function formatDateTime(dateStr) {
    if (!dateStr) return '-';
    try {
        return new Date(dateStr).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch (e) {
        return '-';
    }
}

/**
 * Get bootstrap badge color for severity
 * @param {string} severity - Severity level (critical, high, medium, low)
 * @returns {string} Bootstrap color class
 */
function getSeverityColor(severity) {
    const colors = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'secondary',
        'informational': 'secondary'
    };
    return colors[severity] || 'secondary';
}

/**
 * Get bootstrap badge HTML for severity
 * @param {string} severity - Severity level
 * @returns {string} HTML badge
 */
function getSeverityBadge(severity) {
    return `<span class="badge bg-${getSeverityColor(severity)}">${severity || 'unknown'}</span>`;
}

/**
 * Get bootstrap badge color for status
 * @param {string} status - Status value
 * @returns {string} Bootstrap color class
 */
function getStatusColor(status) {
    const colors = {
        // Cases
        'open': 'primary',
        'in_progress': 'info',
        'on_hold': 'warning',
        'closed': 'dark',
        // Incidents
        'detected': 'primary',
        'investigating': 'info',
        'containment': 'warning',
        'eradication': 'warning',
        'recovery': 'success',
        'post_incident': 'secondary',
        'new': 'primary'
    };
    return colors[status] || 'secondary';
}

/**
 * Get bootstrap badge HTML for status
 * @param {string} status - Status value
 * @returns {string} HTML badge
 */
function getStatusBadge(status) {
    return `<span class="badge bg-${getStatusColor(status)}">${status || 'unknown'}</span>`;
}

/**
 * Get bootstrap badge color for priority
 * @param {string} priority - Priority level
 * @returns {string} Bootstrap color class
 */
function getPriorityColor(priority) {
    const colors = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'secondary'
    };
    return colors[priority] || 'secondary';
}

/**
 * Get bootstrap badge HTML for priority
 * @param {string} priority - Priority level
 * @returns {string} HTML badge
 */
function getPriorityBadge(priority) {
    return `<span class="badge bg-${getPriorityColor(priority)}">${priority || 'unknown'}</span>`;
}

/**
 * Escape HTML special characters
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
    if (!text) return '';
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

/**
 * Build query string from object
 * @param {object} params - Parameters object
 * @returns {string} Query string
 */
function buildQueryString(params) {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
        if (value) qs.set(key, value);
    });
    return qs.toString();
}
