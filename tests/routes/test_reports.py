"""Tests for report generation service and routes."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import os


@pytest.fixture
def mock_llm_enabled():
    """Set LLM as enabled for tests."""
    os.environ['LLM_ENABLED'] = 'true'
    os.environ['LLM_URL'] = 'http://localhost:11434'
    os.environ['LLM_MODEL'] = 'mistral'
    yield
    os.environ['LLM_ENABLED'] = 'false'


class TestReportService:
    """Test ReportService class."""
    
    def test_is_configured_success(self, mock_llm_enabled):
        """Test successful LLM configuration check."""
        from app.services.report_service import ReportService
        
        with patch('app.services.report_service.requests.get') as mock_get:
            mock_get.return_value.status_code = 200
            
            service = ReportService()
            assert service.is_configured() is True
    
    def test_is_configured_failure(self, mock_llm_enabled):
        """Test failed LLM configuration check."""
        from app.services.report_service import ReportService
        
        with patch('app.services.report_service.requests.get') as mock_get:
            mock_get.side_effect = Exception("Connection failed")
            
            service = ReportService()
            assert service.is_configured() is False
    
    def test_call_llm_success(self, mock_llm_enabled):
        """Test successful LLM call."""
        from app.services.report_service import ReportService
        
        with patch('app.services.report_service.requests.post') as mock_post:
            mock_post.return_value.json.return_value = {
                'response': 'This is a test analysis.'
            }
            
            service = ReportService()
            result = service._call_llm("Test prompt")
            
            assert result == 'This is a test analysis.'
            mock_post.assert_called_once()
    
    def test_call_llm_failure(self, mock_llm_enabled):
        """Test failed LLM call."""
        from app.services.report_service import ReportService
        
        with patch('app.services.report_service.requests.post') as mock_post:
            mock_post.side_effect = Exception("Request failed")
            
            service = ReportService()
            with pytest.raises(RuntimeError):
                service._call_llm("Test prompt")
    
    def test_generate_ioc_report(self, mock_llm_enabled):
        """Test IOC report generation."""
        from app.services.report_service import ReportService
        
        with patch.object(ReportService, '_call_llm') as mock_llm, \
             patch.object(ReportService, '_get_ioc_relations') as mock_relations:
            
            # Mock Elasticsearch get
            with patch('app.services.report_service.ElasticsearchService.get') as mock_es_get:
                mock_es_get.return_value = {
                    'id': 'test-ioc-1',
                    'value': '192.168.1.1',
                    'type': 'ipv4',
                    'severity': 'high'
                }
                
                mock_llm.return_value = 'Test analysis for IOC'
                mock_relations.return_value = [
                    {'target_id': 'ioc-2', 'relationship_type': 'communicates-with'}
                ]
                
                service = ReportService()
                result = service.generate_ioc_report('test-ioc-1')
                
                assert result['ioc_id'] == 'test-ioc-1'
                assert result['ioc_type'] == 'ipv4'
                assert result['analysis'] == 'Test analysis for IOC'
                assert result['relations_count'] == 1
    
    def test_generate_ioc_report_not_found(self, mock_llm_enabled):
        """Test IOC report generation with non-existent IOC."""
        from app.services.report_service import ReportService
        
        with patch('app.services.report_service.ElasticsearchService.get') as mock_es_get:
            mock_es_get.return_value = None
            
            service = ReportService()
            with pytest.raises(ValueError, match='not found'):
                service.generate_ioc_report('nonexistent-ioc')
    
    def test_generate_case_report(self, mock_llm_enabled):
        """Test case report generation."""
        from app.services.report_service import ReportService
        
        with patch.object(ReportService, '_call_llm') as mock_llm, \
             patch.object(ReportService, '_get_case_incidents') as mock_incidents, \
             patch.object(ReportService, '_get_case_iocs') as mock_iocs:
            
            with patch('app.services.report_service.ElasticsearchService.get') as mock_es_get:
                mock_es_get.return_value = {
                    'id': 'case-1',
                    'name': 'Test Case',
                    'status': 'open'
                }
                
                mock_llm.return_value = 'Test case analysis'
                mock_incidents.return_value = [{'id': 'inc-1', 'name': 'Incident 1'}]
                mock_iocs.return_value = [{'id': 'ioc-1', 'value': '10.0.0.1'}]
                
                service = ReportService()
                result = service.generate_case_report('case-1')
                
                assert result['case_id'] == 'case-1'
                assert result['case_name'] == 'Test Case'
                assert result['report'] == 'Test case analysis'
                assert result['incidents_count'] == 1
                assert result['iocs_count'] == 1
    
    def test_generate_incident_report(self, mock_llm_enabled):
        """Test incident report generation."""
        from app.services.report_service import ReportService
        
        with patch.object(ReportService, '_call_llm') as mock_llm, \
             patch.object(ReportService, '_get_incident_iocs') as mock_iocs:
            
            with patch('app.services.report_service.ElasticsearchService.get') as mock_es_get:
                mock_es_get.return_value = {
                    'id': 'incident-1',
                    'name': 'Test Incident',
                    'severity': 'high'
                }
                
                mock_llm.return_value = 'Test incident analysis'
                mock_iocs.return_value = [
                    {'id': 'ioc-1', 'value': '10.0.0.1', 'type': 'ipv4'}
                ]
                
                service = ReportService()
                result = service.generate_incident_report('incident-1')
                
                assert result['incident_id'] == 'incident-1'
                assert result['incident_name'] == 'Test Incident'
                assert result['analysis'] == 'Test incident analysis'
                assert result['iocs_count'] == 1


class TestReportRoutes:
    """Test report routes."""
    
    def test_get_report_config_not_admin(self, authenticated_client):
        """Test getting report config without admin permission."""
        response = authenticated_client.get('/api/reports/config')
        # Should return 403 since user is not admin
        assert response.status_code in [403, 401]
    
    def test_generate_ioc_report_disabled(self, authenticated_client):
        """Test generating IOC report when LLM is disabled."""
        os.environ['LLM_ENABLED'] = 'false'
        
        response = authenticated_client.get('/api/reports/iocs/test-ioc-1')
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data
    
    def test_generate_ioc_report_success(self, authenticated_client, mock_llm_enabled):
        """Test successful IOC report generation."""
        with patch('app.routes.reports.report_service.generate_ioc_report') as mock_gen:
            mock_gen.return_value = {
                'ioc_id': 'test-ioc-1',
                'ioc_type': 'ipv4',
                'ioc_value': '192.168.1.1',
                'analysis': 'Test analysis',
                'relations_count': 2,
                'generated_at': '2024-01-01T00:00:00'
            }
            
            response = authenticated_client.get('/api/reports/iocs/test-ioc-1')
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['ioc_id'] == 'test-ioc-1'
            assert data['analysis'] == 'Test analysis'
    
    def test_generate_case_report_success(self, authenticated_client, mock_llm_enabled):
        """Test successful case report generation."""
        with patch('app.routes.reports.report_service.generate_case_report') as mock_gen:
            mock_gen.return_value = {
                'case_id': 'case-1',
                'case_name': 'Test Case',
                'report': 'Test report',
                'incidents_count': 1,
                'iocs_count': 3,
                'generated_at': '2024-01-01T00:00:00'
            }
            
            response = authenticated_client.get('/api/reports/cases/case-1')
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['case_id'] == 'case-1'
            assert data['report'] == 'Test report'
    
    def test_generate_incident_report_success(self, authenticated_client, mock_llm_enabled):
        """Test successful incident report generation."""
        with patch('app.routes.reports.report_service.generate_incident_report') as mock_gen:
            mock_gen.return_value = {
                'incident_id': 'inc-1',
                'incident_name': 'Test Incident',
                'analysis': 'Test analysis',
                'iocs_count': 2,
                'generated_at': '2024-01-01T00:00:00'
            }
            
            response = authenticated_client.get('/api/reports/incidents/inc-1')
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['incident_id'] == 'inc-1'
            assert data['analysis'] == 'Test analysis'
    
    def test_update_report_config_success(self, authenticated_client):
        """Test updating report configuration."""
        config = {
            'enabled': True,
            'url': 'http://localhost:11434',
            'model': 'mistral',
            'api_key': ''
        }
        
        with patch('app.routes.reports.report_service.is_configured') as mock_check:
            mock_check.return_value = True
            
            response = authenticated_client.post(
                '/api/reports/config',
                json=config,
                content_type='application/json'
            )
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] is True
            assert data['configured'] is True
