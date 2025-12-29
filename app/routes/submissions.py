"""Routes for public submissions and submission management."""

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user

from app.decorators import permission_required
from app.services.submission_service import SubmissionService
from app.services.ioc_service import IOCService
from app.services.audit_service import AuditService
from app.models.stix_schema import STIXIndicator

submissions_bp = Blueprint('submissions', __name__, url_prefix='/submissions')
public_bp = Blueprint('public_submissions', __name__, url_prefix='/public-submission')


# ==================== PUBLIC ROUTES ====================

@public_bp.route('/', methods=['GET'])
def public_submission_page():
    """Public submission page (accessible without login)."""
    if not current_app.config.get('PUBLIC_SUBMISSIONS_ENABLED', True):
        return render_template('error.html', error='Public submissions are disabled'), 403
    
    return render_template('public_submission.html')


@public_bp.route('/api/search', methods=['POST', 'GET'])
def public_search():
    """
    Public API - Search for existing IOCs without authentication.
    
    ---
    tags:
      - Public Submissions
    parameters:
      - in: query
        name: q
        schema:
          type: string
        description: IOC value to search for (auto-detects type if not specified)
      - in: query
        name: ioc_type
        schema:
          type: string
        description: Type of IOC (md5, sha256, ipv4, domain, email, url, asn) - optional
    requestBody:
      required: false
      content:
        application/json:
          schema:
            type: object
            properties:
              ioc_type:
                type: string
                description: Type of IOC (md5, sha256, ipv4, domain, email, url, asn)
              ioc_value:
                type: string
                description: Value of the IOC
    responses:
      200:
        description: Search results
        content:
          application/json:
            schema:
              type: object
              properties:
                found:
                  type: boolean
                count:
                  type: integer
                detected_type:
                  type: string
                results:
                  type: array
      400:
        description: Invalid request
    """
    if not current_app.config.get('PUBLIC_SUBMISSIONS_ENABLED', True):
        return jsonify({'error': 'Public submissions are disabled'}), 403
    
    try:
        # Support both GET and POST
        if request.method == 'GET':
            ioc_value = request.args.get('q', '').strip()
            ioc_type = request.args.get('ioc_type', '').lower()
        else:
            data = request.get_json() or {}
            ioc_value = data.get('ioc_value', data.get('q', '')).strip()
            ioc_type = data.get('ioc_type', '').lower()
        
        if not ioc_value:
            return jsonify({'error': 'Missing IOC value (q or ioc_value parameter)'}), 400
        
        # Auto-detect IOC type if not provided
        from app.utils.pattern_generator import PatternGenerator
        detected_type = None
        if not ioc_type:
            detected_type = PatternGenerator.auto_detect_type(ioc_value)
            if not detected_type:
                return jsonify({
                    'found': False,
                    'error': f'Could not auto-detect IOC type for: {ioc_value}',
                    'results': []
                }), 400
            ioc_type = detected_type
        
        service = SubmissionService()
        result = service.public_search(ioc_type, ioc_value)
        
        # Add detected type to response
        result['detected_type'] = detected_type or ioc_type
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@public_bp.route('/api/submit', methods=['POST'])
def public_submit():
    """
    Public API - Submit a new external IOC.
    
    ---
    tags:
      - Public Submissions
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - ioc_type
              - ioc_value
            properties:
              ioc_type:
                type: string
              ioc_value:
                type: string
              submitter_email:
                type: string
              submitter_name:
                type: string
              submitter_organization:
                type: string
              description:
                type: string
              reason:
                type: string
              tags:
                type: array
                items:
                  type: string
              confidence:
                type: string
                enum: [high, medium, low]
    responses:
      201:
        description: Submission created
        content:
          application/json:
            schema:
              type: object
              properties:
                id:
                  type: string
                status:
                  type: string
                message:
                  type: string
      400:
        description: Invalid request
      403:
        description: Public submissions disabled
    """
    if not current_app.config.get('PUBLIC_SUBMISSIONS_ENABLED', True):
        return jsonify({'error': 'Public submissions are disabled'}), 403
    
    try:
        data = request.get_json()
        
        # Required fields
        ioc_type = data.get('ioc_type', '').lower()
        ioc_value = data.get('ioc_value', '').strip()
        
        if not ioc_type or not ioc_value:
            return jsonify({'error': 'Missing required fields: ioc_type, ioc_value'}), 400
        
        # Optional fields
        submitter_email = data.get('submitter_email', '')
        submitter_name = data.get('submitter_name', '')
        submitter_organization = data.get('submitter_organization', '')
        description = data.get('description', '')
        reason = data.get('reason', '')
        tags = data.get('tags', [])
        confidence = data.get('confidence', 'medium')
        
        # Validate required anonymous fields if enabled
        if current_app.config.get('PUBLIC_SUBMISSIONS_ALLOW_ANONYMOUS', True):
            if not submitter_email:
                return jsonify({'error': 'Email is required for anonymous submissions'}), 400
        
        service = SubmissionService()
        submission = service.create_submission(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            submitter_email=submitter_email,
            submitter_name=submitter_name,
            submitter_organization=submitter_organization,
            description=description,
            reason=reason,
            tags=tags,
            confidence=confidence
        )
        
        return jsonify({
            'id': submission['id'],
            'status': submission['status'],
            'message': 'Submission created successfully',
            'matched_count': len(submission.get('matched_iocs', []))
        }), 201
    
    except ValueError as e:
        current_app.logger.error(f"ValueError in public_submit: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.exception(f"Exception in public_submit: {str(e)}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500


# ==================== AUTHENTICATED ROUTES ====================

@submissions_bp.route('/', methods=['GET'])
@login_required
@permission_required('submission.view')
def list_submissions():
    """List submissions (authenticated users only)."""
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', None)
    
    service = SubmissionService()
    result = service.list_submissions(page=page, status=status)
    
    return render_template('submissions/list.html', submissions=result)


@submissions_bp.route('/api/list', methods=['GET'])
@login_required
@permission_required('submission.view')
def api_list_submissions():
    """
    API - List submissions.
    
    ---
    tags:
      - Submissions
    security:
      - bearerAuth: []
    parameters:
      - in: query
        name: page
        schema:
          type: integer
        description: Page number
      - in: query
        name: status
        schema:
          type: string
          enum: [pending, processed, created_ioc, rejected]
        description: Filter by status
    responses:
      200:
        description: List of submissions
    """
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', None)
    
    service = SubmissionService()
    result = service.list_submissions(page=page, status=status)
    
    return jsonify(result), 200


@submissions_bp.route('/<submission_id>', methods=['GET'])
@login_required
@permission_required('submission.view')
def view_submission(submission_id):
    """View submission details."""
    service = SubmissionService()
    submission = service.get_submission(submission_id)
    
    if not submission:
        return render_template('error.html', error='Submission not found'), 404
    
    # Get matched IOCs if any
    matched_iocs = []
    if submission.get('matched_iocs'):
        ioc_service = IOCService()
        for ioc_id in submission['matched_iocs']:
            ioc = ioc_service.get_ioc(ioc_id)
            if ioc:
                matched_iocs.append(ioc)
    
    return render_template('submissions/detail.html',
                         submission=submission,
                         matched_iocs=matched_iocs)


@submissions_bp.route('/api/<submission_id>', methods=['GET'])
@login_required
@permission_required('submission.view')
def api_get_submission(submission_id):
    """
    API - Get submission details.
    
    ---
    tags:
      - Submissions
    security:
      - bearerAuth: []
    parameters:
      - in: path
        name: submission_id
        required: true
        schema:
          type: string
    responses:
      200:
        description: Submission details
      404:
        description: Submission not found
    """
    service = SubmissionService()
    submission = service.get_submission(submission_id)
    
    if not submission:
        return jsonify({'error': 'Submission not found'}), 404
    
    return jsonify(submission), 200


@submissions_bp.route('/<submission_id>/create-ioc', methods=['POST'])
@login_required
@permission_required('submission.create')
def create_ioc_from_submission(submission_id):
    """Create an IOC from a submission."""
    try:
        submission_service = SubmissionService()
        submission = submission_service.get_submission(submission_id)
        
        if not submission:
            return jsonify({'error': 'Submission not found'}), 404
        
        data = request.get_json()
        
        # Create IOC from submission data
        ioc_service = IOCService()
        
        # Create STIX indicator
        stix_indicator = STIXIndicator.create(
            ioc_type=submission['ioc_type'],
            value=submission['ioc_value'],
            labels=data.get('labels', submission.get('tags', [])),
            name=data.get('name', f"{submission['ioc_type'].upper()}: {submission['ioc_value']}"),
            description=data.get('description', submission.get('description'))
        )
        
        # Create IOC using the IOCService create method
        ioc_dict, is_new = ioc_service.create(
            ioc_type=submission['ioc_type'],
            value=submission['ioc_value'],
            labels=data.get('labels', submission.get('tags', [])),
            name=data.get('name', f"{submission['ioc_type'].upper()}: {submission['ioc_value']}"),
            description=data.get('description', submission.get('description')),
            threat_level=data.get('threat_level', 'medium'),
            tlp=data.get('tlp', 'amber'),
            confidence=data.get('confidence', submission.get('confidence', 'medium')),
            campaigns=data.get('campaigns', []),
            user_id=current_user.id,
            username=current_user.username
        )
        
        # Update the created IOC with response_actions if provided
        if data.get('response_actions'):
            ioc_service.update(
                ioc_dict['id'],
                {
                    'x_metadata': {
                        'response_actions': data.get('response_actions')
                    }
                },
                user_id=current_user.id,
                username=current_user.username
            )
        
        # Update submission to link created IOC
        submission_service.update_submission(
            submission_id=submission_id,
            status='created_ioc',
            created_ioc_id=ioc_dict.get('id'),
            analyst_user_id=current_user.id,
            analyst_username=current_user.username,
            response_actions=data.get('response_actions'),
            analyst_notes=data.get('analyst_notes')
        )
        
        # Audit log
        audit_service = AuditService()
        audit_service.log(
            action='create',
            entity_type='ioc',
            entity_id=ioc_dict.get('id'),
            user_id=current_user.id,
            username=current_user.username,
            changes={'from_submission': submission_id}
        )
        
        return jsonify({
            'message': 'IOC created from submission',
            'ioc_id': ioc_dict.get('id'),
            'submission_id': submission_id
        }), 201
    
    except Exception as e:
        current_app.logger.exception(f"Error creating IOC from submission {submission_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@submissions_bp.route('/<submission_id>/api/create-ioc', methods=['POST'])
@login_required
@permission_required('submission.create')
def api_create_ioc_from_submission(submission_id):
    """
    API - Create IOC from submission.
    
    ---
    tags:
      - Submissions
    security:
      - bearerAuth: []
    parameters:
      - in: path
        name: submission_id
        required: true
        schema:
          type: string
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              name:
                type: string
              description:
                type: string
              labels:
                type: array
                items:
                  type: string
              threat_level:
                type: string
              tlp:
                type: string
              confidence:
                type: string
              risk_score:
                type: integer
              campaigns:
                type: array
              response_actions:
                type: string
              analyst_notes:
                type: string
    responses:
      201:
        description: IOC created
      404:
        description: Submission not found
    """
    return create_ioc_from_submission(submission_id)


@submissions_bp.route('/<submission_id>/review', methods=['POST'])
@login_required
@permission_required('submission.manage')
def review_submission(submission_id):
    """Review and update submission."""
    try:
        data = request.get_json()
        
        service = SubmissionService()
        submission = service.update_submission(
            submission_id=submission_id,
            analyst_user_id=current_user.id,
            analyst_username=current_user.username,
            status=data.get('status', 'processed'),
            analyst_notes=data.get('analyst_notes'),
            response_actions=data.get('response_actions')
        )
        
        return jsonify({
            'message': 'Submission updated',
            'submission': submission
        }), 200
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        current_app.logger.exception(f"Error reviewing submission {submission_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@submissions_bp.route('/<submission_id>/api/review', methods=['POST'])
@login_required
@permission_required('submission.manage')
def api_review_submission(submission_id):
    """
    API - Review submission.
    
    ---
    tags:
      - Submissions
    security:
      - bearerAuth: []
    parameters:
      - in: path
        name: submission_id
        required: true
        schema:
          type: string
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              status:
                type: string
                enum: [pending, processed, created_ioc, rejected]
              analyst_notes:
                type: string
              response_actions:
                type: string
    responses:
      200:
        description: Submission updated
      404:
        description: Submission not found
    """
    return review_submission(submission_id)


@submissions_bp.route('/<submission_id>/reject', methods=['POST'])
@login_required
@permission_required('submission.manage')
def reject_submission(submission_id):
    """Reject a submission."""
    try:
        data = request.get_json()
        
        service = SubmissionService()
        submission = service.reject_submission(
            submission_id=submission_id,
            rejection_reason=data.get('rejection_reason'),
            analyst_user_id=current_user.id,
            analyst_username=current_user.username
        )
        
        return jsonify({
            'message': 'Submission rejected',
            'submission': submission
        }), 200
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        current_app.logger.exception(f"Error rejecting submission {submission_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@submissions_bp.route('/<submission_id>/api/reject', methods=['POST'])
@login_required
@permission_required('submission.manage')
def api_reject_submission(submission_id):
    """
    API - Reject submission.
    
    ---
    tags:
      - Submissions
    security:
      - bearerAuth: []
    parameters:
      - in: path
        name: submission_id
        required: true
        schema:
          type: string
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              rejection_reason:
                type: string
    responses:
      200:
        description: Submission rejected
      404:
        description: Submission not found
    """
    return reject_submission(submission_id)
