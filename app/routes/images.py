"""Routes for image uploads and management."""

from flask import Blueprint, request, jsonify, send_file, abort
from flask_login import login_required, current_user
from werkzeug.exceptions import BadRequest

from app.decorators import permission_required
from app.services.image_service import ImageService

images_bp = Blueprint('images', __name__, url_prefix='/api/images')


@images_bp.route('', methods=['POST'])
@login_required
def upload_image():
    """
    Upload an image for a comment, timeline event, or other entity.
    
    ---
    tags:
      - Images
    summary: Upload Image
    requestBody:
      required: true
      content:
        multipart/form-data:
          schema:
            type: object
            required:
              - file
              - entity_type
              - entity_id
            properties:
              file:
                type: string
                format: binary
                description: Image file
              entity_type:
                type: string
                enum: [comment, timeline_event, ioc, case, incident]
                description: Type of entity
              entity_id:
                type: string
                description: ID of the entity
    responses:
      201:
        description: Image uploaded successfully
      400:
        description: Invalid request or file
      403:
        description: Not authorized
    """
    service = ImageService()
    
    # Check if file is in request
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    entity_type = request.form.get('entity_type', '').lower()
    entity_id = request.form.get('entity_id', '')
    
    if not entity_type or not entity_id:
        return jsonify({'error': 'Missing entity_type or entity_id'}), 400
    
    # Validate entity type
    valid_types = ['comment', 'timeline_event', 'ioc', 'case', 'incident', 'checklist']
    if entity_type not in valid_types:
        return jsonify({'error': f'Invalid entity_type. Must be one of: {", ".join(valid_types)}'}), 400
    
    try:
        image = service.upload_image(
            file=file,
            user_id=current_user.id,
            entity_type=entity_type,
            entity_id=entity_id
        )
        return jsonify(image), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500


@images_bp.route('/<image_id>/view', methods=['GET'])
def view_image(image_id):
    """View/download an image."""
    service = ImageService()
    
    result = service.get_image_file(image_id)
    if not result:
        abort(404)
    
    file_content, mime_type = result
    
    try:
        from io import BytesIO
        return send_file(
            BytesIO(file_content),
            mimetype=mime_type,
            as_attachment=False
        )
    except Exception:
        abort(500)


@images_bp.route('/<image_id>/metadata', methods=['GET'])
def get_image_metadata(image_id):
    """Get image metadata."""
    service = ImageService()
    
    image = service.get_image_metadata(image_id)
    if not image:
        abort(404)
    
    return jsonify(image)


@images_bp.route('', methods=['GET'])
@login_required
def list_images():
    """Get all images for an entity via query parameters."""
    entity_type = request.args.get('entity_type', '').lower()
    entity_id = request.args.get('entity_id', '')
    
    if not entity_type or not entity_id:
        return jsonify({'error': 'Missing entity_type or entity_id'}), 400
    
    service = ImageService()
    
    valid_types = ['comment', 'timeline_event', 'ioc', 'case', 'incident', 'checklist']
    if entity_type not in valid_types:
        return jsonify({'error': f'Invalid entity_type. Must be one of: {", ".join(valid_types)}'}), 400
    
    images = service.get_entity_images(entity_type, entity_id)
    return jsonify({'images': images})


@images_bp.route('/<image_id>', methods=['DELETE'])
@login_required
def delete_image(image_id):
    """Delete an image."""
    service = ImageService()
    
    # Check authorization
    image = service.get_image_metadata(image_id)
    if not image:
        abort(404)
    
    # Only allow owner or admin to delete
    if image['uploaded_by_id'] != current_user.id and not current_user.has_permission('image.delete'):
        abort(403)
    
    success = service.delete_image(image_id)
    if not success:
        return jsonify({'error': 'Failed to delete image'}), 500
    
    return '', 204


@images_bp.route('/entity/<entity_type>/<entity_id>', methods=['GET'])
@login_required
def get_entity_images(entity_type, entity_id):
    """Get all images for an entity."""
    service = ImageService()
    
    valid_types = ['comment', 'timeline_event', 'ioc', 'case', 'incident']
    if entity_type not in valid_types:
        return jsonify({'error': f'Invalid entity_type. Must be one of: {", ".join(valid_types)}'}), 400
    
    images = service.get_entity_images(entity_type, entity_id)
    return jsonify({'images': images})
