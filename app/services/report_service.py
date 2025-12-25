"""Service for generating reports using LLM (Ollama or OpenAI-compatible)."""

import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
from app.services.elasticsearch_service import ElasticsearchService
from app.services.cache_service import CacheService
from app.services.ioc_service import IOCService
from app.services.case_service import CaseService, IncidentService
from app.config import Config
import os


class ReportService:
    """Service to generate reports using LLM providers."""
    
    def __init__(self):
        """Initialize report service."""
        self.es = ElasticsearchService()
        self.cache = CacheService()
        self.ioc_service = IOCService()
        self.case_service = CaseService()
        self.incident_service = IncidentService()
        
        # Try to load config from Elasticsearch first
        try:
            config = self.es.get('app_config', 'llm_config')
            if config:
                self.llm_url = config.get('url', os.getenv('LLM_URL', 'http://ollama:11434'))
                self.llm_model = config.get('model', os.getenv('LLM_MODEL', 'mistral'))
                self.llm_api_key = config.get('api_key', os.getenv('LLM_API_KEY', ''))
                self.custom_prompt_ioc = config.get('custom_prompt_ioc', '')
                self.custom_prompt_case = config.get('custom_prompt_case', '')
                self.custom_prompt_incident = config.get('custom_prompt_incident', '')
                return
        except Exception:
            pass
        
        # Fall back to environment variables
        self.llm_url = os.getenv('LLM_URL', 'http://ollama:11434')
        self.llm_model = os.getenv('LLM_MODEL', 'mistral')
        self.llm_api_key = os.getenv('LLM_API_KEY', '')
        self.custom_prompt_ioc = ''
        self.custom_prompt_case = ''
        self.custom_prompt_incident = ''
    
    def is_configured(self) -> bool:
        """Check if LLM is properly configured."""
        try:
            response = requests.get(f"{self.llm_url}/api/tags", timeout=2)
            return response.status_code == 200
        except requests.RequestException:
            return False
    
    def _call_llm(self, prompt: str) -> str:
        """
        Call LLM API with prompt.
        
        Args:
            prompt: The prompt to send to LLM
            
        Returns:
            Generated response from LLM
        """
        # Reload config from Elasticsearch on each call to ensure latest settings
        import sys
        try:
            config = self.es.get('app_config', 'llm_config')
            if config:
                old_url = self.llm_url
                self.llm_url = config.get('url', os.getenv('LLM_URL', 'http://ollama:11434'))
                self.llm_model = config.get('model', os.getenv('LLM_MODEL', 'mistral'))
                self.llm_api_key = config.get('api_key', os.getenv('LLM_API_KEY', ''))
                print(f"DEBUG: Loaded LLM config from ES. URL: {old_url} -> {self.llm_url}", file=sys.stderr)
        except Exception as e:
            print(f"DEBUG: Failed to reload LLM config: {str(e)}", file=sys.stderr)
        
        try:
            print(f"DEBUG: Using LLM URL: {self.llm_url}", file=sys.stderr)
            headers = {'Content-Type': 'application/json'}
            if self.llm_api_key:
                headers['Authorization'] = f'Bearer {self.llm_api_key}'
            
            payload = {
                'model': self.llm_model,
                'prompt': prompt,
                'stream': False,
            }
            
            response = requests.post(
                f"{self.llm_url}/api/generate",
                json=payload,
                headers=headers,
                timeout=120
            )
            response.raise_for_status()
            
            data = response.json()
            return data.get('response', '').strip()
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to call LLM: {str(e)}")
    
    def generate_ioc_report(self, ioc_id: str) -> Dict[str, Any]:
        """
        Generate a report for an IOC and its relations.
        
        Args:
            ioc_id: The IOC document ID
            
        Returns:
            Report data with analysis and relations
        """
        # Get IOC using the IOC service
        ioc = self.ioc_service.get(ioc_id)
        if not ioc:
            raise ValueError(f"IOC {ioc_id} not found")
        
        # Get relations
        relations = self._get_ioc_relations(ioc_id)
        
        # Build prompt
        prompt = self._build_ioc_prompt(ioc, relations)
        
        # Generate analysis
        analysis = self._call_llm(prompt)
        
        return {
            'ioc_id': ioc_id,
            'ioc_value': ioc.get('value') or ioc.get('pattern', ''),
            'ioc_type': ioc.get('type', 'unknown'),
            'generated_at': datetime.utcnow().isoformat(),
            'analysis': analysis,
            'relations_count': len(relations)
        }
    
    def generate_case_report(self, case_id: str) -> Dict[str, Any]:
        """
        Generate a report for a case.
        
        Args:
            case_id: The case document ID
            
        Returns:
            Report data with case summary
        """
        # Get case using the case service
        case = self.case_service.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        
        # Get incidents in case
        incidents = self._get_case_incidents(case_id)
        
        # Get IOCs related to case
        iocs = self._get_case_iocs(case_id)
        
        # Build prompt
        prompt = self._build_case_prompt(case, incidents, iocs)
        
        # Generate report
        report = self._call_llm(prompt)
        
        return {
            'case_id': case_id,
            'case_name': case.get('name') or case.get('title', 'Unknown'),
            'generated_at': datetime.utcnow().isoformat(),
            'report': report,
            'incidents_count': len(incidents),
            'iocs_count': len(iocs)
        }
    
    def generate_incident_report(self, incident_id: str) -> Dict[str, Any]:
        """
        Generate a report for an incident.
        
        Args:
            incident_id: The incident document ID
            
        Returns:
            Report data with incident analysis
        """
        # Get incident using the incident service
        incident = self.incident_service.get_incident(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        
        # Get related IOCs
        iocs = self._get_incident_iocs(incident_id)
        
        # Build prompt
        prompt = self._build_incident_prompt(incident, iocs)
        
        # Generate analysis
        analysis = self._call_llm(prompt)
        
        return {
            'incident_id': incident_id,
            'incident_name': incident.get('name') or incident.get('title', 'Unknown'),
            'generated_at': datetime.utcnow().isoformat(),
            'analysis': analysis,
            'iocs_count': len(iocs)
        }
    
    def _get_ioc_relations(self, ioc_id: str) -> List[Dict]:
        """Get relations for an IOC."""
        query = {
            'query': {
                'bool': {
                    'should': [
                        {'term': {'source_id': ioc_id}},
                        {'term': {'target_id': ioc_id}}
                    ]
                }
            },
            'size': 100
        }
        result = self.es.search('ioc_relations', query)
        items = []
        for hit in result.get('hits', {}).get('hits', []):
            doc = hit['_source']
            doc['id'] = hit['_id']
            items.append(doc)
        return items
    
    def _get_case_incidents(self, case_id: str) -> List[Dict]:
        """Get incidents for a case."""
        # Get case document first
        case = self.case_service.get_case(case_id)
        if not case:
            return []
        
        incident_ids = case.get('incident_ids', [])
        if not incident_ids:
            return []
        
        # Fetch each incident
        items = []
        for incident_id in incident_ids[:10]:  # Limit to 10
            try:
                incident = self.incident_service.get_incident(incident_id)
                if incident:
                    incident['id'] = incident_id
                    items.append(incident)
            except Exception:
                pass
        return items
    
    def _get_case_iocs(self, case_id: str) -> List[Dict]:
        """Get IOCs for a case."""
        # Get case document first
        case = self.case_service.get_case(case_id)
        if not case:
            return []
        
        ioc_ids = case.get('ioc_ids', [])
        if not ioc_ids:
            return []
        
        # Fetch each IOC
        items = []
        for ioc_id in ioc_ids[:20]:  # Limit to 20
            try:
                ioc = self.ioc_service.get(ioc_id)
                if ioc:
                    ioc['id'] = ioc_id
                    items.append(ioc)
            except Exception:
                pass
        return items
    
    def _get_incident_iocs(self, incident_id: str) -> List[Dict]:
        """Get IOCs for an incident."""
        # Get incident document first
        incident = self.incident_service.get_incident(incident_id)
        if not incident:
            return []
        
        ioc_ids = incident.get('ioc_ids', [])
        if not ioc_ids:
            return []
        
        # Fetch each IOC
        items = []
        for ioc_id in ioc_ids[:20]:  # Limit to 20
            try:
                ioc = self.ioc_service.get(ioc_id)
                if ioc:
                    ioc['id'] = ioc_id
                    items.append(ioc)
            except Exception:
                pass
        return items
    
    def _build_ioc_prompt(self, ioc: Dict, relations: List[Dict]) -> str:
        """Build prompt for IOC analysis."""
        # Get IOC value from either value field or extract from STIX pattern
        ioc_value = ioc.get('value') or ioc.get('pattern', '')
        if ioc_value.startswith('[') and '=' in ioc_value:
            # Extract value from STIX pattern like [file:hashes.SHA1 = '...']
            ioc_value = ioc_value.split("'")[1] if "'" in ioc_value else ioc_value
        
        relations_text = '\n'.join([
            f"- {r.get('relationship_type', 'related')}: {r.get('target_id') if r.get('source_id') == ioc.get('id') else r.get('source_id')}"
            for r in relations[:15]  # Limit to 15 relations
        ]) or "No relations found"
        
        # Use custom prompt if available
        if self.custom_prompt_ioc:
            try:
                return self.custom_prompt_ioc.format(
                    type=ioc.get('type'),
                    value=ioc_value,
                    severity=ioc.get('x_metadata', {}).get('threat_level', ioc.get('severity', 'unknown')),
                    description=ioc.get('description', 'N/A'),
                    relations=relations_text
                )
            except KeyError:
                pass
        
        return f"""Analyze this Indicator of Compromise (IOC) and provide a concise threat assessment:

IOC Type: {ioc.get('type')}
IOC Value: {ioc_value}
Severity: {ioc.get('x_metadata', {}).get('threat_level', ioc.get('severity', 'unknown'))}
Description: {ioc.get('description', 'N/A')}
Created: {ioc.get('created', ioc.get('created_at', 'Unknown'))}

Related Indicators ({len(relations)}):
{relations_text}

Please provide in **Markdown format**:
1. What this indicator represents
2. Potential threats it indicates
3. Recommended mitigation steps
4. Connection to other indicators and their significance"""
    
    def _build_case_prompt(self, case: Dict, incidents: List[Dict], iocs: List[Dict]) -> str:
        """Build prompt for case analysis."""
        # Format incident details
        incidents_text = '\n'.join([
            f"- {i.get('title', i.get('name', 'Unknown'))}: {i.get('description', 'N/A')} (Type: {i.get('category', i.get('type', 'N/A'))})"
            for i in incidents[:5]
        ]) or "No incidents"
        
        # Format IOC details - handle STIX pattern format
        iocs_text = '\n'.join([
            f"- {i.get('type')}: {i.get('value') or i.get('pattern', 'N/A')} (Severity: {i.get('x_metadata', {}).get('threat_level', i.get('severity', 'N/A'))})"
            for i in iocs[:15]
        ]) or "No IOCs"
        
        # Use custom prompt if available
        if self.custom_prompt_case:
            try:
                return self.custom_prompt_case.format(
                    name=case.get('name', case.get('title', 'Unknown')),
                    status=case.get('status'),
                    priority=case.get('priority'),
                    description=case.get('description', 'N/A'),
                    incidents_count=len(incidents),
                    incidents=incidents_text,
                    iocs_count=len(iocs),
                    iocs=iocs_text
                )
            except KeyError:
                pass
        
        return f"""Generate a comprehensive investigation report for this security case:

Case Name: {case.get('name', case.get('title', 'Unknown'))}
Status: {case.get('status')}
Priority: {case.get('priority')}
Description: {case.get('description', 'N/A')}
Created: {case.get('created_at', 'Unknown')}

Incidents ({len(incidents)}):
{incidents_text}

Indicators of Compromise ({len(iocs)}):
{iocs_text}

Please provide in **Markdown format**:
1. Executive Summary
2. Timeline of Events
3. Threat Assessment
4. Compromised Assets
5. Indicators and their significance
6. Recommended Actions
7. Risk Level Assessment"""
    
    def _build_incident_prompt(self, incident: Dict, iocs: List[Dict]) -> str:
        """Build prompt for incident analysis."""
        # Format IOC details - handle STIX pattern format
        iocs_text = '\n'.join([
            f"- {i.get('type')}: {i.get('value') or i.get('pattern', 'N/A')} (Severity: {i.get('x_metadata', {}).get('threat_level', i.get('severity', 'N/A'))})"
            for i in iocs[:15]
        ]) or "No IOCs"
        
        # Use custom prompt if available
        if self.custom_prompt_incident:
            try:
                return self.custom_prompt_incident.format(
                    name=incident.get('title', incident.get('name', 'Unknown')),
                    description=incident.get('description', 'N/A'),
                    type=incident.get('category', incident.get('type', 'Unknown')),
                    severity=incident.get('severity', 'unknown'),
                    status=incident.get('status'),
                    iocs_count=len(iocs),
                    iocs=iocs_text
                )
            except KeyError:
                pass
        
        return f"""Analyze this security incident and generate a brief threat report:

Incident Name: {incident.get('title', incident.get('name', 'Unknown'))}
Description: {incident.get('description', 'N/A')}
Type: {incident.get('category', incident.get('type', 'Unknown'))}
Severity: {incident.get('severity', 'unknown')}
Status: {incident.get('status')}
Created: {incident.get('created_at', 'Unknown')}
Detected: {incident.get('detected_at', 'Unknown')}

Associated Indicators ({len(iocs)}):
{iocs_text}

Please provide in **Markdown format**:
1. Incident Summary
2. Attack Vector Analysis
3. Affected Systems
4. Indicators and their role in the incident
5. Immediate Actions Required
6. Long-term Recommendations"""
