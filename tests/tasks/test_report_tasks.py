"""Tests for report generation tasks."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import os


class TestReportTasks:
    """Test report generation tasks."""
    
    def test_generate_incident_reports_disabled(self):
        """Test generate_incident_reports task when LLM is disabled."""
        from app.tasks.report_tasks import generate_incident_reports
        
        os.environ['LLM_ENABLED'] = 'false'
        
        result = generate_incident_reports()
        
        assert result['status'] == 'skipped'
        assert result['reason'] == 'LLM not enabled'
    
    def test_generate_incident_reports_success(self):
        """Test successful batch report generation."""
        from app.tasks.report_tasks import generate_incident_reports
        
        os.environ['LLM_ENABLED'] = 'true'
        
        with patch('app.tasks.report_tasks.ElasticsearchService') as mock_es_class, \
             patch('app.tasks.report_tasks.ReportService') as mock_report_class, \
             patch('app.tasks.report_tasks.AuditService') as mock_audit_class:
            
            # Mock ES search
            mock_es = MagicMock()
            mock_es_class.return_value = mock_es
            mock_es.search.return_value = {
                'hits': {
                    'hits': [
                        {
                            '_id': 'incident-1',
                            '_source': {
                                'id': 'incident-1',
                                'name': 'Test Incident 1',
                                'status': 'open'
                            }
                        },
                        {
                            '_id': 'incident-2',
                            '_source': {
                                'id': 'incident-2',
                                'name': 'Test Incident 2',
                                'status': 'open'
                            }
                        }
                    ]
                }
            }
            
            # Mock report service
            mock_report = MagicMock()
            mock_report_class.return_value = mock_report
            mock_report.generate_incident_report.return_value = {
                'incident_id': 'incident-1',
                'analysis': 'Test analysis'
            }
            
            # Mock audit service
            mock_audit = MagicMock()
            mock_audit_class.return_value = mock_audit
            
            result = generate_incident_reports()
            
            assert result['status'] == 'completed'
            assert result['generated'] == 2
            assert result['failed'] == 0
            assert result['total'] == 2
    
    def test_generate_incident_reports_partial_failure(self):
        """Test batch report generation with some failures."""
        from app.tasks.report_tasks import generate_incident_reports
        
        os.environ['LLM_ENABLED'] = 'true'
        
        with patch('app.tasks.report_tasks.ElasticsearchService') as mock_es_class, \
             patch('app.tasks.report_tasks.ReportService') as mock_report_class, \
             patch('app.tasks.report_tasks.AuditService') as mock_audit_class:
            
            # Mock ES
            mock_es = MagicMock()
            mock_es_class.return_value = mock_es
            mock_es.search.return_value = {
                'hits': {
                    'hits': [
                        {
                            '_id': 'incident-1',
                            '_source': {
                                'id': 'incident-1',
                                'name': 'Test Incident 1',
                                'status': 'open'
                            }
                        }
                    ]
                }
            }
            
            # Mock report service - first call succeeds, second fails
            mock_report = MagicMock()
            mock_report_class.return_value = mock_report
            mock_report.generate_incident_report.side_effect = Exception("LLM error")
            
            # Mock audit
            mock_audit = MagicMock()
            mock_audit_class.return_value = mock_audit
            
            result = generate_incident_reports()
            
            assert result['status'] == 'completed'
            assert result['generated'] == 0
            assert result['failed'] == 1
