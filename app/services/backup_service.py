"""Backup and restore service for database and configurations."""

import json
import gzip
import shutil
import os
from datetime import datetime
from pathlib import Path
from app.services.elasticsearch_service import ElasticsearchService


class BackupService:
    """Handle backup and restore operations."""
    
    def __init__(self):
        self.es_service = ElasticsearchService()
        self.backup_dir = Path('backups')
        self.backup_dir.mkdir(exist_ok=True)
    
    def create_backup(self, include_indices=None):
        """
        Create a backup of Elasticsearch data and configurations.
        
        Args:
            include_indices: List of indices to backup. If None, backups all.
        
        Returns:
            dict with backup_id, timestamp, size, indices_count
        """
        if include_indices is None:
            # Get all available indices from Elasticsearch
            try:
                all_indices = self.es_service.client.indices.get_alias(index="*")
                include_indices = [idx for idx in all_indices.keys() if idx.startswith(ElasticsearchService.INDEX_PREFIX)]
            except:
                # Fallback to default indices
                include_indices = [
                    'elaslip_iocs', 'elaslip_cases', 'elaslip_incidents', 'elaslip_checklists',
                    'elaslip_webhooks', 'elaslip_api_keys', 'elaslip_audit_logs'
                ]
        else:
            # Add prefix to indices if not already present
            include_indices = [
                idx if idx.startswith(ElasticsearchService.INDEX_PREFIX) 
                else f"{ElasticsearchService.INDEX_PREFIX}{idx}"
                for idx in include_indices
            ]
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_id = f'backup_{timestamp}'
        backup_path = self.backup_dir / backup_id
        backup_path.mkdir(exist_ok=True)
        
        backup_data = {
            'timestamp': timestamp,
            'backup_id': backup_id,
            'indices': {}
        }
        
        try:
            # Backup each index
            total_size = 0
            indices_backed = 0
            
            for index_name in include_indices:
                try:
                    # Get all documents from index
                    docs = self._get_all_documents(index_name)
                    
                    if docs:
                        backup_data['indices'][index_name] = {
                            'doc_count': len(docs),
                            'documents': docs
                        }
                        indices_backed += 1
                except Exception as e:
                    backup_data['indices'][index_name] = {
                        'error': str(e),
                        'doc_count': 0
                    }
            
            # Write backup data to JSON file
            backup_file = backup_path / 'data.json'
            with open(backup_file, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, default=str)
            
            # Compress backup
            compressed_file = self.backup_dir / f'{backup_id}.tar.gz'
            shutil.make_archive(
                str(self.backup_dir / backup_id),
                'gztar',
                self.backup_dir,
                backup_id
            )
            
            # Get file size
            if compressed_file.exists():
                total_size = compressed_file.stat().st_size
                # Clean up uncompressed directory
                shutil.rmtree(backup_path)
            
            return {
                'success': True,
                'backup_id': backup_id,
                'timestamp': timestamp,
                'size': total_size,
                'size_mb': round(total_size / 1024 / 1024, 2),
                'indices_count': indices_backed,
                'message': f'Backup completed successfully. {indices_backed} indices backed up.'
            }
        
        except Exception as e:
            # Clean up on error
            if backup_path.exists():
                shutil.rmtree(backup_path)
            return {
                'success': False,
                'error': str(e),
                'message': f'Backup failed: {str(e)}'
            }
    
    def restore_backup(self, backup_id, overwrite=False):
        """
        Restore data from a backup.
        
        Args:
            backup_id: Backup ID to restore (without .tar.gz extension)
            overwrite: If True, delete existing indices before restore. Otherwise merge.
        
        Returns:
            dict with restore status and result
        """
        backup_file = self.backup_dir / f'{backup_id}.tar.gz'
        
        if not backup_file.exists():
            return {
                'success': False,
                'error': f'Backup file not found: {backup_id}',
                'message': f'Backup "{backup_id}" does not exist'
            }
        
        extract_dir = None
        try:
            # Extract backup to temporary directory
            extract_dir = self.backup_dir / f'restore_temp_{backup_id}'
            extract_dir.mkdir(exist_ok=True)
            
            # Extract tar.gz file
            shutil.unpack_archive(str(backup_file), str(extract_dir), 'gztar')
            
            # The extraction creates a directory with the backup_id name inside
            backup_content_dir = extract_dir / backup_id
            
            # If the content wasn't directly extracted, check for it
            if not backup_content_dir.exists():
                # The files might be directly in extract_dir
                backup_content_dir = extract_dir
            
            # Read backup data
            data_file = backup_content_dir / 'data.json'
            if not data_file.exists():
                return {
                    'success': False,
                    'error': 'data.json not found in backup',
                    'message': 'Backup file is corrupted'
                }
            
            with open(data_file, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            
            # Restore each index
            restored_count = 0
            failed_count = 0
            total_docs = 0
            
            for index_name, index_data in backup_data['indices'].items():
                if 'error' in index_data:
                    failed_count += 1
                    continue
                
                try:
                    docs = index_data.get('documents', [])
                    
                    if not docs:
                        continue
                    
                    # If overwrite is True, delete the index first
                    if overwrite:
                        try:
                            self.es_service.client.indices.delete(index=index_name)
                        except:
                            pass  # Index might not exist
                    
                    # Restore documents
                    for doc in docs:
                        doc_id = doc.get('_id', doc.get('id'))
                        # Use the full document as body, but ensure _id is not in body
                        body = {k: v for k, v in doc.items() if k != '_id'}
                        
                        self.es_service.client.index(
                            index=index_name,
                            id=doc_id,
                            document=body
                        )
                        total_docs += 1
                    
                    restored_count += 1
                
                except Exception as e:
                    import traceback
                    print(f"Error restoring {index_name}: {str(e)}")
                    traceback.print_exc()
                    failed_count += 1
            
            return {
                'success': True,
                'backup_id': backup_id,
                'indices_restored': restored_count,
                'indices_failed': failed_count,
                'documents_restored': total_docs,
                'message': f'Restore completed. {restored_count} indices restored with {total_docs} documents.'
            }
        
        except Exception as e:
            import traceback
            print(f"Restore error: {str(e)}")
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e),
                'message': f'Restore failed: {str(e)}'
            }
        
        finally:
            # Clean up extracted files
            if extract_dir and extract_dir.exists():
                try:
                    shutil.rmtree(extract_dir)
                except:
                    pass
    
    def list_backups(self):
        """List all available backups."""
        backups = []
        
        for backup_file in sorted(self.backup_dir.glob('backup_*.tar.gz'), reverse=True):
            try:
                stat = backup_file.stat()
                # Remove both .tar.gz extensions
                backup_id = backup_file.name.replace('.tar.gz', '')
                
                # Extract timestamp from backup_id
                timestamp_str = backup_id.replace('backup_', '')
                
                backups.append({
                    'backup_id': backup_id,
                    'timestamp': timestamp_str,
                    'size': stat.st_size,
                    'size_mb': round(stat.st_size / 1024 / 1024, 2),
                    'created': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
            except Exception:
                pass
        
        return backups
    
    def delete_backup(self, backup_id):
        """Delete a backup file."""
        backup_file = self.backup_dir / f'{backup_id}.tar.gz'
        
        if not backup_file.exists():
            return {
                'success': False,
                'error': f'Backup not found: {backup_id}'
            }
        
        try:
            backup_file.unlink()
            return {
                'success': True,
                'message': f'Backup "{backup_id}" deleted successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': f'Failed to delete backup: {str(e)}'
            }
    
    def _get_all_documents(self, index_name):
        """Get all documents from an index."""
        try:
            # Use scroll API to get all documents
            results = self.es_service.client.search(
                index=index_name,
                scroll='2m',
                size=10000,
                query={'match_all': {}}
            )
            
            documents = []
            scroll_id = results.get('_scroll_id')
            
            # Collect initial results
            for hit in results['hits']['hits']:
                doc = hit['_source']
                doc['_id'] = hit['_id']
                documents.append(doc)
            
            # Scroll through remaining results
            while len(results['hits']['hits']) > 0:
                results = self.es_service.client.scroll(
                    scroll_id=scroll_id,
                    scroll='2m'
                )
                
                for hit in results['hits']['hits']:
                    doc = hit['_source']
                    doc['_id'] = hit['_id']
                    documents.append(doc)
            
            return documents
        
        except Exception as e:
            raise Exception(f'Failed to retrieve documents from {index_name}: {str(e)}')
    
    def get_backup_info(self, backup_id):
        """Get detailed information about a backup."""
        backup_file = self.backup_dir / f'{backup_id}.tar.gz'
        
        if not backup_file.exists():
            return {'error': 'Backup not found'}
        
        # Extract and read backup metadata
        try:
            temp_dir = self.backup_dir / f'temp_info_{backup_id}'
            shutil.unpack_archive(str(backup_file), str(self.backup_dir), 'gztar')
            extract_dir = self.backup_dir / backup_id
            
            data_file = extract_dir / 'data.json'
            with open(data_file, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            
            # Calculate stats
            total_docs = 0
            indices_info = {}
            
            for index_name, index_data in backup_data['indices'].items():
                doc_count = index_data.get('doc_count', 0)
                total_docs += doc_count
                indices_info[index_name] = doc_count
            
            # Clean up
            shutil.rmtree(extract_dir)
            
            stat = backup_file.stat()
            return {
                'backup_id': backup_id,
                'timestamp': backup_data.get('timestamp'),
                'size_mb': round(stat.st_size / 1024 / 1024, 2),
                'total_documents': total_docs,
                'indices': indices_info
            }
        
        except Exception as e:
            return {'error': str(e)}
