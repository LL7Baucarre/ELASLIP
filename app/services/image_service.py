"""Service for handling image uploads and attachments."""

import os
import uuid
from datetime import datetime
from typing import Dict, Optional, Tuple
from werkzeug.utils import secure_filename
import hashlib

from app.services.elasticsearch_service import ElasticsearchService


class ImageService:
    """Service for managing image uploads for comments, timeline events, etc."""
    
    # Supported image types
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'}
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    
    def __init__(self):
        self.es = ElasticsearchService()
        self.upload_dir = os.getenv('UPLOAD_DIR', '/app/uploads')
        self._ensure_upload_dir()
    
    def _ensure_upload_dir(self):
        """Ensure upload directory exists."""
        if not os.path.exists(self.upload_dir):
            os.makedirs(self.upload_dir, exist_ok=True)
    
    def _allowed_file(self, filename: str) -> bool:
        """Check if file extension is allowed."""
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in self.ALLOWED_EXTENSIONS
    
    def upload_image(self, file, user_id: str, entity_type: str, entity_id: str) -> Dict:
        """
        Upload an image and store metadata in Elasticsearch.
        
        Args:
            file: FileStorage object from Flask
            user_id: User ID uploading the image
            entity_type: Type of entity (comment, timeline_event, ioc, case, incident)
            entity_id: ID of the entity
        
        Returns:
            Image metadata document
        
        Raises:
            ValueError: If file is invalid
        """
        if not file or file.filename == '':
            raise ValueError('No file provided')
        
        if not self._allowed_file(file.filename):
            raise ValueError(f'File type not allowed. Allowed types: {", ".join(self.ALLOWED_EXTENSIONS)}')
        
        # Check file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > self.MAX_FILE_SIZE:
            raise ValueError(f'File size exceeds maximum of {self.MAX_FILE_SIZE / 1024 / 1024}MB')
        
        # Read file content
        file_content = file.read()
        
        # Generate file hash for deduplication
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        # Generate unique filename
        original_filename = secure_filename(file.filename)
        ext = original_filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4()}.{ext}"
        filepath = os.path.join(self.upload_dir, unique_filename)
        
        # Save file
        with open(filepath, 'wb') as f:
            f.write(file_content)
        
        # Create metadata document
        now = datetime.utcnow().isoformat() + 'Z'
        image_id = f"image--{uuid.uuid4()}"
        
        image_doc = {
            'id': image_id,
            'filename': original_filename,
            'stored_filename': unique_filename,
            'file_hash': file_hash,
            'file_size': file_size,
            'mime_type': file.content_type or 'image/unknown',
            'entity_type': entity_type,
            'entity_id': entity_id,
            'uploaded_by_id': user_id,
            'uploaded_at': now,
            'url': f'/api/images/{image_id}/view'
        }
        
        self.es.index('elaslip_images', image_id, image_doc)
        
        return image_doc
    
    def get_image_metadata(self, image_id: str) -> Optional[Dict]:
        """Get image metadata."""
        try:
            result = self.es.get('elaslip_images', image_id)
            if result:
                image = result['_source']
                image['id'] = result['_id']
                return image
        except Exception:
            pass
        return None
    
    def get_image_file(self, image_id: str) -> Optional[Tuple[bytes, str]]:
        """
        Get image file content.
        
        Returns:
            Tuple of (file_content, mime_type) or None if not found
        """
        metadata = self.get_image_metadata(image_id)
        if not metadata:
            return None
        
        filepath = os.path.join(self.upload_dir, metadata['stored_filename'])
        if not os.path.exists(filepath):
            return None
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            return content, metadata.get('mime_type', 'image/unknown')
        except Exception:
            return None
    
    def delete_image(self, image_id: str) -> bool:
        """Delete an image."""
        metadata = self.get_image_metadata(image_id)
        if not metadata:
            return False
        
        # Delete file
        filepath = os.path.join(self.upload_dir, metadata['stored_filename'])
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception:
            pass
        
        # Delete metadata
        try:
            self.es.delete('elaslip_images', image_id)
            return True
        except Exception:
            return False
    
    def get_entity_images(self, entity_type: str, entity_id: str) -> list:
        """Get all images for an entity."""
        try:
            query = {
                'query': {
                    'bool': {
                        'must': [
                            {'term': {'entity_type': entity_type}},
                            {'term': {'entity_id': entity_id}}
                        ]
                    }
                },
                'size': 100,
                'sort': [{'uploaded_at': {'order': 'desc'}}]
            }
            result = self.es.search('elaslip_images', query)
            images = []
            for hit in result.get('hits', {}).get('hits', []):
                image = hit['_source']
                image['id'] = hit['_id']
                images.append(image)
            return images
        except Exception:
            return []
