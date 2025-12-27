"""Routes for FinOps (LLM token usage tracking)."""

from flask import Blueprint, jsonify, request
from flask_login import login_required
from app.services.finops_service import FinOpsService

finops_bp = Blueprint('finops', __name__, url_prefix='/api/finops')

@finops_bp.route('/token-usage', methods=['GET'])
@login_required
def get_token_usage():
    """Get token usage timeline data."""
    try:
        finops = FinOpsService()
        
        # Get query parameters
        time_window = request.args.get('time_window', 'day')  # hour, day, month
        report_types_str = request.args.get('report_types', '')  # comma-separated
        limit_days = int(request.args.get('limit_days', 30))
        
        # Parse report types
        report_types = None
        if report_types_str:
            report_types = [t.strip() for t in report_types_str.split(',') if t.strip()]
        
        # Get timeline data
        timeline = finops.get_token_usage_timeline(
            time_window=time_window,
            report_types=report_types,
            limit_days=limit_days
        )
        
        # Get breakdown by type
        breakdown = finops.get_token_usage_by_report_type(limit_days=limit_days)
        
        # Get overall statistics
        stats = finops.get_statistics(limit_days=limit_days)
        
        # Get top consumers
        top_consumers = finops.get_top_token_consumers(limit=10, limit_days=limit_days)
        
        return jsonify({
            'status': 'success',
            'timeline': timeline,
            'breakdown': breakdown,
            'statistics': stats,
            'top_consumers': top_consumers,
            'time_window': time_window,
            'limit_days': limit_days
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@finops_bp.route('/token-usage/timeline', methods=['GET'])
@login_required
def get_token_usage_timeline():
    """Get token usage timeline (simplified)."""
    try:
        finops = FinOpsService()
        
        time_window = request.args.get('time_window', 'day')
        report_types_str = request.args.get('report_types', '')
        limit_days = int(request.args.get('limit_days', 30))
        
        report_types = None
        if report_types_str:
            report_types = [t.strip() for t in report_types_str.split(',') if t.strip()]
        
        timeline = finops.get_token_usage_timeline(
            time_window=time_window,
            report_types=report_types,
            limit_days=limit_days
        )
        
        return jsonify({
            'status': 'success',
            'timeline': timeline
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@finops_bp.route('/token-usage/breakdown', methods=['GET'])
@login_required
def get_token_breakdown():
    """Get token usage breakdown by report type."""
    try:
        finops = FinOpsService()
        
        limit_days = int(request.args.get('limit_days', 30))
        breakdown = finops.get_token_usage_by_report_type(limit_days=limit_days)
        
        return jsonify({
            'status': 'success',
            'breakdown': breakdown
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@finops_bp.route('/token-usage/statistics', methods=['GET'])
@login_required
def get_token_statistics():
    """Get token usage statistics."""
    try:
        finops = FinOpsService()
        
        limit_days = int(request.args.get('limit_days', 30))
        stats = finops.get_statistics(limit_days=limit_days)
        
        return jsonify({
            'status': 'success',
            'statistics': stats
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@finops_bp.route('/token-usage/top-consumers', methods=['GET'])
@login_required
def get_top_token_consumers():
    """Get reports that consumed the most tokens."""
    try:
        finops = FinOpsService()
        
        limit = int(request.args.get('limit', 10))
        limit_days = int(request.args.get('limit_days', 30))
        
        consumers = finops.get_top_token_consumers(limit=limit, limit_days=limit_days)
        
        return jsonify({
            'status': 'success',
            'consumers': consumers
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500
