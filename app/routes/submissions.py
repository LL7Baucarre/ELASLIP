"""Routes for public submissions and submission management."""

from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user

from app.decorators import permission_required
from app.services.submission_service import SubmissionService
from app.services.stix_service import STIXService
from app.services.audit_service import AuditService
from app.services.notification_service import NotificationService
from app.models.stix_schema import STIXIndicator

submissions_bp = Blueprint('submissions', __name__, url_prefix='/submissions')
public_bp = Blueprint('public_submissions', __name__, url_prefix='/public-submission')


# ==================== PUBLIC ROUTES ====================

@public_bp.route('/', methods=['GET'])
def public_submission_page():
    """Public submission page (accessible without login)."""
    if not current_app.config.get('PUBLIC_SEARCH_ENABLED', True):
        return render_template('error.html', error='Public search is disabled'), 403
    
    allow_anonymous = current_app.config.get('PUBLIC_SUBMISSIONS_ALLOW_ANONYMOUS', True)
    return render_template('public_submission.html', allow_anonymous=allow_anonymous)


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
    if not current_app.config.get('PUBLIC_SEARCH_ENABLED', True):
        return jsonify({'error': 'Public search is disabled'}), 403
    
    audit = AuditService()
    
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
                # Log failed search
                audit.log(
                    action='public_search',
                    entity_type='ioc',
                    entity_id=ioc_value,
                    username='anonymous',
                    entity_name=f'Public Search: {ioc_value}',
                    changes={
                        'status': 'failed',
                        'reason': 'auto_detect_failed',
                        'ioc_value': ioc_value,
                        'ioc_type': ioc_type or 'unknown'
                    },
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent')
                )
                return jsonify({
                    'found': False,
                    'error': f'Could not auto-detect IOC type for: {ioc_value}',
                    'results': []
                }), 400
            ioc_type = detected_type
        
        service = SubmissionService()
        max_results = current_app.config.get('PUBLIC_SUBMISSIONS_MAX_RESULTS', 50)
        result = service.public_search(ioc_type, ioc_value, max_results=max_results)
        
        # Add detected type to response
        result['detected_type'] = detected_type or ioc_type
        
        # Log successful search
        audit.log(
            action='public_search',
            entity_type='ioc',
            entity_id=ioc_value,
            username='anonymous',
            entity_name=f'Public Search: {ioc_value} ({ioc_type})',
            changes={
                'status': 'success',
                'ioc_type': ioc_type,
                'ioc_value': ioc_value,
                'found': result.get('found', False),
                'count': result.get('count', 0)
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify(result), 200
    except Exception as e:
        # Log error
        audit.log(
            action='public_search',
            entity_type='ioc',
            entity_id='unknown',
            username='anonymous',
            entity_name='Public Search',
            changes={
                'status': 'error',
                'error': str(e)
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        return jsonify({'error': str(e)}), 500


@public_bp.route('/api/status/<submission_id>', methods=['GET'])
def public_get_submission_status(submission_id):
    """
    Public API - Get submission status by ID.
    Allows submitters to check the status of their submission.
    
    Returns status information including:
    - pending: Awaiting review
    - duplicate: Marked as duplicate of another submission
    - created_ioc: IOC was created from this submission
    - rejected: Submission was rejected
    - processed: Submission was processed
    """
    try:
        service = SubmissionService()
        submission = service.get_submission(submission_id)
        
        if not submission:
            return jsonify({'error': 'Submission not found'}), 404
        
        # Determine message based on status
        messages = {
            'pending': 'Your submission is pending review by our analysts.',
            'duplicate': 'This submission is a duplicate of another submission that was submitted earlier.',
            'created_ioc': 'An IOC has been created from your submission and is now in our database.',
            'rejected': 'Your submission has been reviewed and rejected.',
            'processed': 'Your submission has been processed.'
        }
        
        # Get info about the duplicate if it exists
        original_info = None
        if submission.get('duplicate_of'):
            try:
                original = service.get_submission(submission['duplicate_of'])
                if original:
                    original_info = {
                        'submission_id': original['id'],
                        'submitted_at': original.get('created_at'),
                        'submitter': original.get('submitter_name') or original.get('submitter_email') or 'Anonymous'
                    }
            except:
                pass
        
        response = {
            'submission_id': submission_id,
            'status': submission['status'],
            'message': messages.get(submission['status'], 'Unknown status'),
            'submitted_at': submission.get('created_at'),
            'ioc_type': submission['ioc_type'],
            'ioc_value': submission['ioc_value'],
            'duplicate_of': original_info
        }
        
        # Add created IOC info if applicable
        if submission.get('created_ioc_id'):
            response['created_ioc_id'] = submission['created_ioc_id']
        
        # Add rejection reason if applicable
        if submission.get('analyst_notes') and submission['status'] == 'rejected':
            response['rejection_reason'] = submission['analyst_notes']
        
        return jsonify(response), 200
    
    except Exception as e:
        current_app.logger.exception(f"Error getting submission status: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


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
        description: Public search disabled
    """
    if not current_app.config.get('PUBLIC_SEARCH_ENABLED', True):
        return jsonify({'error': 'Public search is disabled'}), 403
    
    if not current_app.config.get('PUBLIC_SUBMISSIONS_SUBMIT_ENABLED', True):
        return jsonify({'error': 'Public IOC submissions are not available at this time'}), 403
    
    audit = AuditService()
    
    try:
        data = request.get_json()
        
        # Required fields
        ioc_type = data.get('ioc_type', '').lower()
        ioc_value = data.get('ioc_value', '').strip()
        
        if not ioc_type or not ioc_value:
            # Log failed submission attempt
            audit.log(
                action='public_submit',
                entity_type='submission',
                entity_id='unknown',
                username='anonymous',
                entity_name='Public IOC Submission',
                changes={
                    'status': 'failed',
                    'reason': 'missing_required_fields',
                    'ioc_type': ioc_type,
                    'ioc_value': ioc_value
                },
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
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
                # Log failed submission attempt
                audit.log(
                    action='public_submit',
                    entity_type='submission',
                    entity_id=ioc_value,
                    username='anonymous',
                    entity_name=f'Public IOC Submission: {ioc_value}',
                    changes={
                        'status': 'failed',
                        'reason': 'missing_email',
                        'ioc_type': ioc_type,
                        'ioc_value': ioc_value
                    },
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent')
                )
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
        
        # Dispatch webhook for public submission
        from app.tasks.webhook_tasks import dispatch_webhook
        try:
            dispatch_webhook.delay('public_submission.created', {
                'submission_id': submission['id'],
                'ioc_type': ioc_type,
                'ioc_value': ioc_value,
                'submitter_email': submitter_email,
                'submitter_name': submitter_name,
                'submitter_organization': submitter_organization,
                'description': description,
                'reason': reason,
                'tags': tags,
                'confidence': confidence,
                'matched_count': len(submission.get('matched_iocs', [])),
                'timestamp': datetime.utcnow().isoformat()
            })
        except Exception as e:
            current_app.logger.warning(f"Failed to dispatch webhook for public submission: {str(e)}")
        
        # Send notification to admins about new submission
        try:
            notification = NotificationService()
            # Get admin users and notify them
            from app.services.elasticsearch_service import ElasticsearchService
            es = ElasticsearchService()
            
            # Query for admin users
            admin_query = {'query': {'term': {'is_admin': True}}, 'size': 100}
            result = es.search('elaslip_users', admin_query)
            
            for hit in result.get('hits', {}).get('hits', []):
                admin_user = hit['_source']
                notification.notify_submission_received(
                    admin_user_id=admin_user.get('id'),
                    submission_id=submission['id'],
                    source=submitter_email or submitter_name or 'Anonymous'
                )
        except Exception as e:
            current_app.logger.warning(f"Failed to send notification for submission: {str(e)}")
        
        # Log successful submission
        audit.log(
            action='public_submit',
            entity_type='submission',
            entity_id=submission['id'],
            username=submitter_email or 'anonymous',
            entity_name=f'Public IOC Submission: {ioc_value} ({ioc_type})',
            changes={
                'status': 'success',
                'ioc_type': ioc_type,
                'ioc_value': ioc_value,
                'submitter_email': submitter_email,
                'submitter_name': submitter_name,
                'submitter_organization': submitter_organization,
                'confidence': confidence,
                'matched_count': len(submission.get('matched_iocs', []))
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({
            'id': submission['id'],
            'status': submission['status'],
            'message': 'Submission created successfully',
            'matched_count': len(submission.get('matched_iocs', []))
        }), 201
    
    except ValueError as e:
        current_app.logger.error(f"ValueError in public_submit: {str(e)}")
        
        # Log error
        audit.log(
            action='public_submit',
            entity_type='submission',
            entity_id='unknown',
            username='anonymous',
            entity_name='Public IOC Submission',
            changes={
                'status': 'error',
                'error': str(e)
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.exception(f"Exception in public_submit: {str(e)}")
        
        # Log error
        audit.log(
            action='public_submit',
            entity_type='submission',
            entity_id='unknown',
            username='anonymous',
            entity_name='Public IOC Submission',
            changes={
                'status': 'error',
                'error': str(e)
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
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
      - APIKey: []
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
    
    # Get matched STIX objects if any
    matched_iocs = []
    if submission.get('matched_iocs'):
        stix_service = STIXService()
        for stix_id in submission['matched_iocs']:
            stix_obj = stix_service.get_sdo(stix_id)
            if stix_obj:
                matched_iocs.append(stix_obj)
    
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
      - APIKey: []
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
    """Create a STIX object from a submission."""
    try:
        submission_service = SubmissionService()
        submission = submission_service.get_submission(submission_id)
        
        if not submission:
            return jsonify({'error': 'Submission not found'}), 404
        
        data = request.get_json()
        
        # Create STIX object from submission data
        stix_service = STIXService()
        
        # Create STIX indicator using the service
        # Map confidence string to STIX confidence integer (0-100)
        confidence_map = {'low': 25, 'medium': 50, 'high': 75, 'very-high': 90}
        confidence_str = data.get('confidence', submission.get('confidence', 'medium'))
        confidence_int = confidence_map.get(confidence_str, 50) if isinstance(confidence_str, str) else 50
        
        stix_obj = stix_service.create_sdo(
            sdo_type='indicator',
            data={
                'pattern': f"[file:hashes.MD5 = '{submission['ioc_value']}']" if submission['ioc_type'] == 'md5' 
                    else f"[file:hashes.SHA-1 = '{submission['ioc_value']}']" if submission['ioc_type'] == 'sha1'
                    else f"[file:hashes.SHA-256 = '{submission['ioc_value']}']" if submission['ioc_type'] == 'sha256'
                    else f"[ipv4-addr:value = '{submission['ioc_value']}']" if submission['ioc_type'] == 'ipv4'
                    else f"[ipv6-addr:value = '{submission['ioc_value']}']" if submission['ioc_type'] == 'ipv6'
                    else f"[domain-name:value = '{submission['ioc_value']}']" if submission['ioc_type'] == 'domain'
                    else f"[email-addr:value = '{submission['ioc_value']}']" if submission['ioc_type'] == 'email'
                    else f"[url:value = '{submission['ioc_value']}']" if submission['ioc_type'] == 'url'
                    else f"[network-traffic:dst_ref.value = '{submission['ioc_value']}']",
                'pattern_type': 'stix',
                'labels': data.get('labels', submission.get('tags', [])),
                'name': data.get('name', f"{submission['ioc_type'].upper()}: {submission['ioc_value']}"),
                'description': data.get('description', submission.get('description')),
                'confidence': confidence_int,
                'valid_from': datetime.utcnow().isoformat() + 'Z',
                'x_ioc_type': submission['ioc_type'],
                'x_ioc_value': submission['ioc_value'],
                'x_threat_level': data.get('threat_level', 'medium'),
                'x_tlp': data.get('tlp', 'amber'),
                'x_metadata': {
                    'source': 'submission',
                    'submission_id': submission_id,
                    'response_actions': data.get('response_actions')
                }
            },
            user_id=current_user.id,
            username=current_user.username
        )
        
        # Update submission to link created STIX object
        submission_service.update_submission(
            submission_id=submission_id,
            status='created_ioc',
            created_ioc_id=stix_obj.get('id'),
            analyst_user_id=current_user.id,
            analyst_username=current_user.username,
            response_actions=data.get('response_actions'),
            analyst_notes=data.get('analyst_notes')
        )
        
        # Audit log
        audit_service = AuditService()
        audit_service.log(
            action='create',
            entity_type='stix',
            entity_id=stix_obj.get('id'),
            user_id=current_user.id,
            username=current_user.username,
            changes={'from_submission': submission_id}
        )
        
        return jsonify({
            'message': 'STIX object created from submission',
            'stix_id': stix_obj.get('id'),
            'submission_id': submission_id
        }), 201
    
    except Exception as e:
        current_app.logger.exception(f"Error creating STIX object from submission {submission_id}: {str(e)}")
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
      - APIKey: []
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
      - APIKey: []
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
      - APIKey: []
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


@submissions_bp.route('/<submission_id>/duplicates', methods=['GET'])
@login_required
@permission_required('submission.view')
def get_submission_duplicates(submission_id):
    """Get duplicate submissions for a given submission."""
    try:
        service = SubmissionService()
        duplicates = service.find_duplicate_submissions(submission_id)
        
        return render_template('submissions/duplicates.html',
                             submission_id=submission_id,
                             duplicates=duplicates)
    except Exception as e:
        current_app.logger.exception(f"Error getting duplicates for {submission_id}: {str(e)}")
        return render_template('error.html', error='Failed to load duplicates'), 500


@submissions_bp.route('/<submission_id>/api/duplicates', methods=['GET'])
@login_required
@permission_required('submission.view')
def api_get_submission_duplicates(submission_id):
    """API - Get duplicate submissions."""
    try:
        service = SubmissionService()
        submission = service.get_submission(submission_id)
        if not submission:
            return jsonify({'error': 'Submission not found'}), 404
        
        duplicates = service.find_duplicate_submissions(submission_id)
        
        return jsonify({
            'submission_id': submission_id,
            'duplicates': duplicates,
            'count': len(duplicates)
        }), 200
    
    except Exception as e:
        current_app.logger.exception(f"Error getting duplicates: {str(e)}")
        return jsonify({'error': str(e)}), 500


@submissions_bp.route('/<submission_id>/api/mark-duplicate', methods=['POST'])
@login_required
@permission_required('submission.manage')
def api_mark_duplicate(submission_id):
    """API - Mark submission as duplicate of another."""
    try:
        data = request.get_json()
        original_id = data.get('original_submission_id')
        
        if not original_id:
            return jsonify({'error': 'original_submission_id is required'}), 400
        
        service = SubmissionService()
        result = service.mark_duplicate(submission_id, original_id)
        
        return jsonify({
            'message': 'Submission marked as duplicate',
            'submission': result
        }), 200
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        current_app.logger.exception(f"Error marking duplicate: {str(e)}")
        return jsonify({'error': str(e)}), 500


@submissions_bp.route('/api/merge-duplicates', methods=['POST'])
@login_required
@permission_required('submission.manage')
def api_merge_duplicates():
    """API - Merge multiple duplicate submissions."""
    try:
        data = request.get_json()
        submission_ids = data.get('submission_ids', [])
        primary_id = data.get('primary_submission_id')
        
        if not submission_ids or len(submission_ids) < 2:
            return jsonify({'error': 'At least 2 submission IDs required'}), 400
        
        service = SubmissionService()
        result = service.merge_duplicate_submissions(submission_ids, primary_id)
        
        return jsonify({
            'message': 'Submissions merged successfully',
            'primary_submission': result
        }), 200
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.exception(f"Error merging duplicates: {str(e)}")
        return jsonify({'error': str(e)}), 500
