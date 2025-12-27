"""Service for generating reports using LLM (Ollama or OpenAI-compatible)."""

import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
from app.services.elasticsearch_service import ElasticsearchService
from app.services.cache_service import CacheService
from app.services.ioc_service import IOCService
from app.services.case_service import CaseService, IncidentService, TimelineService
from app.services.comment_service import CommentService
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
        self.timeline_service = TimelineService()
        self.comment_service = CommentService()
        
        # Try to load config from Elasticsearch first
        try:
            response = self.es.get('elasmisp_app_config', 'llm_config')
            if response and response.get('found'):
                config = response.get('_source', {})
                self.llm_url = config.get('url', os.getenv('LLM_URL', 'http://ollama:11434')).rstrip('/')
                self.llm_model = config.get('model', os.getenv('LLM_MODEL', 'mistral'))
                self.llm_api_key = config.get('api_key', os.getenv('LLM_API_KEY', ''))
                self.llm_provider = config.get('provider', os.getenv('LLM_PROVIDER', 'auto'))  # auto, ollama, openai
                self.generation_language = config.get('generation_language', 'en')
                self.custom_prompt_ioc = config.get('custom_prompt_ioc', '')
                self.custom_prompt_case = config.get('custom_prompt_case', '')
                self.custom_prompt_incident = config.get('custom_prompt_incident', '')
                self.custom_prompt_checklist = config.get('custom_prompt_checklist', '')
                return
        except Exception:
            pass
        
        # Fall back to environment variables
        self.llm_url = os.getenv('LLM_URL', 'http://ollama:11434').rstrip('/')
        self.llm_model = os.getenv('LLM_MODEL', 'mistral')
        self.llm_api_key = os.getenv('LLM_API_KEY', '')
        self.llm_provider = os.getenv('LLM_PROVIDER', 'auto')  # auto, ollama, openai
        self.generation_language = os.getenv('LLM_GENERATION_LANGUAGE', 'en')
        self.custom_prompt_ioc = ''
        self.custom_prompt_case = ''
        self.custom_prompt_incident = ''
        self.custom_prompt_checklist = ''
    
    def is_configured(self) -> bool:
        """Check if LLM is properly configured."""
        provider = self._detect_llm_provider()
        try:
            if provider == 'openai':
                # Try OpenAI-compatible endpoint
                headers = {}
                if self.llm_api_key:
                    # Encode API key properly for HTTP headers
                    api_key_str = self.llm_api_key if isinstance(self.llm_api_key, str) else str(self.llm_api_key)
                    try:
                        # Try to use the key as-is if it's ASCII
                        api_key_str.encode('ascii')
                        headers['Authorization'] = f'Bearer {api_key_str}'
                    except UnicodeEncodeError:
                        # If not ASCII, encode as UTF-8 bytes then decode as latin-1 for HTTP headers
                        api_key_latin1 = api_key_str.encode('utf-8').decode('latin-1')
                        headers['Authorization'] = f'Bearer {api_key_latin1}'
                response = requests.get(f"{self.llm_url}/v1/models", headers=headers, timeout=2)
            else:
                # Try Ollama endpoint
                response = requests.get(f"{self.llm_url}/api/tags", timeout=2)
            return response.status_code == 200
        except requests.RequestException:
            return False
    
    def _detect_llm_provider(self) -> str:
        """
        Auto-detect LLM provider type (ollama, openai, or custom).
        
        Returns:
            'openai' for OpenAI-compatible endpoints, 'ollama' for Ollama
        """
        if self.llm_provider != 'auto':
            return self.llm_provider
        
        # Auto-detection: try OpenAI endpoint first
        try:
            headers = {}
            if self.llm_api_key:
                # Encode API key properly for HTTP headers
                api_key_str = self.llm_api_key if isinstance(self.llm_api_key, str) else str(self.llm_api_key)
                try:
                    # Try to use the key as-is if it's ASCII
                    api_key_str.encode('ascii')
                    headers['Authorization'] = f'Bearer {api_key_str}'
                except UnicodeEncodeError:
                    # If not ASCII, encode as UTF-8 bytes then decode as latin-1 for HTTP headers
                    api_key_latin1 = api_key_str.encode('utf-8').decode('latin-1')
                    headers['Authorization'] = f'Bearer {api_key_latin1}'
            response = requests.get(f"{self.llm_url}/v1/models", headers=headers, timeout=3)
            if response.status_code == 200:
                print(f"[LLM DETECT] Detected OpenAI-compatible provider at {self.llm_url}")
                return 'openai'
        except requests.RequestException:
            pass
        
        # Fall back to Ollama
        try:
            response = requests.get(f"{self.llm_url}/api/tags", timeout=3)
            if response.status_code == 200:
                print(f"[LLM DETECT] Detected Ollama provider at {self.llm_url}")
                return 'ollama'
        except requests.RequestException:
            pass
        
        # Default to OpenAI if URL contains 'openai' or v1/chat/completions pattern
        if 'openai' in self.llm_url or '/v1/' in self.llm_url:
            print(f"[LLM DETECT] Detected OpenAI-compatible by URL pattern")
            return 'openai'
        
        # Default to Ollama
        print(f"[LLM DETECT] Defaulting to Ollama provider")
        return 'ollama'
    
    def _call_llm(self, prompt: str) -> tuple:
        """
        Call LLM API with prompt (supports Ollama and OpenAI-compatible endpoints).
        
        Args:
            prompt: The prompt to send to LLM
            
        Returns:
            Tuple of (response, token_usage) where token_usage = {'prompt_tokens': int, 'completion_tokens': int}
        """
        # Reload config from Elasticsearch on each call to ensure latest settings
        import sys
        try:
            response = self.es.get('elasmisp_app_config', 'llm_config')
            if response and response.get('found'):
                config = response.get('_source', {})
                old_lang = self.generation_language
                self.llm_url = config.get('url', os.getenv('LLM_URL', 'http://ollama:11434')).rstrip('/')
                self.llm_model = config.get('model', os.getenv('LLM_MODEL', 'mistral'))
                self.llm_api_key = config.get('api_key', os.getenv('LLM_API_KEY', ''))
                self.llm_provider = config.get('provider', os.getenv('LLM_PROVIDER', 'auto'))
                self.generation_language = config.get('generation_language', 'en')
                self.custom_prompt_ioc = config.get('custom_prompt_ioc', '')
                self.custom_prompt_case = config.get('custom_prompt_case', '')
                self.custom_prompt_incident = config.get('custom_prompt_incident', '')
                self.custom_prompt_checklist = config.get('custom_prompt_checklist', '')
                print(f"[LLM CONFIG LOADED] Language: {old_lang} -> {self.generation_language}")
        except Exception as e:
            print(f"[LLM CONFIG ERROR] Failed to reload: {str(e)}")
        
        try:
            print(f"[LLM CALL] Using LLM URL: {self.llm_url}")
            print(f"[LLM CALL] Generation language: {self.generation_language}")
            
            # Detect provider
            provider = self._detect_llm_provider()
            print(f"[LLM CALL] Provider: {provider}, Model: {self.llm_model}, Language: {self.generation_language}")
            
            if provider == 'openai':
                print(f"[LLM CALL] Calling OpenAI-compatible endpoint...")
                return self._call_openai_llm(prompt)
            else:
                print(f"[LLM CALL] Calling Ollama endpoint...")
                return self._call_ollama_llm(prompt)
        except requests.RequestException as e:
            print(f"[LLM ERROR] RequestException: {str(e)}")
            raise RuntimeError(f"Failed to call LLM: {str(e)}")
        except Exception as e:
            print(f"[LLM ERROR] General exception: {type(e).__name__}: {str(e)}")
            raise
    
    def _call_ollama_llm(self, prompt: str) -> tuple:
        """Call Ollama API endpoint."""
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
        response_text = data.get('response', '').strip()
        
        # Extract token usage from response
        token_usage = {
            'prompt_tokens': data.get('prompt_eval_count', 0),
            'completion_tokens': data.get('eval_count', 0)
        }
        
        print(f"[LLM RESPONSE] First 100 chars: {response_text[:100]}")
        return response_text, token_usage
    
    def _call_openai_llm(self, prompt: str) -> tuple:
        """Call OpenAI-compatible API endpoint."""
        headers = {'Content-Type': 'application/json'}
        if self.llm_api_key:
            # Encode API key properly for HTTP headers
            api_key_str = self.llm_api_key if isinstance(self.llm_api_key, str) else str(self.llm_api_key)
            try:
                # Try to use the key as-is if it's ASCII
                api_key_str.encode('ascii')
                headers['Authorization'] = f'Bearer {api_key_str}'
            except UnicodeEncodeError:
                # If not ASCII, encode as UTF-8 bytes then decode as latin-1 for HTTP headers
                api_key_latin1 = api_key_str.encode('utf-8').decode('latin-1')
                headers['Authorization'] = f'Bearer {api_key_latin1}'
        
        # OpenAI-compatible payload
        payload = {
            'model': self.llm_model,
            'messages': [
                {
                    'role': 'user',
                    'content': prompt
                }
            ],
            'stream': False,
            'temperature': 0.7,
            'max_tokens': 4000,
        }
        
        request_url = f"{self.llm_url}/v1/chat/completions"
        print(f"[OPENAI LLM] Posting to {request_url} with model {self.llm_model}")
        
        response = requests.post(
            request_url,
            json=payload,
            headers=headers,
            timeout=120
        )
        
        print(f"[OPENAI LLM] Response status: {response.status_code}")
        response.raise_for_status()
        
        data = response.json()
        print(f"[OPENAI LLM] Response keys: {list(data.keys())}")
        
        # Extract response from OpenAI format
        if 'choices' in data and len(data['choices']) > 0:
            response_text = data['choices'][0].get('message', {}).get('content', '').strip()
        else:
            response_text = str(data)
        
        # Clean up markdown code blocks if LLM wrapped the response
        # Remove triple backticks with optional language specification
        if response_text.startswith('```'):
            # Remove opening ```markdown or ``` or ```python etc
            lines = response_text.split('\n')
            if lines[0].startswith('```'):
                lines = lines[1:]  # Remove first line with backticks
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]  # Remove last line with backticks
            response_text = '\n'.join(lines).strip()
        
        # Extract token usage from response
        usage = data.get('usage', {})
        token_usage = {
            'prompt_tokens': usage.get('prompt_tokens', 0),
            'completion_tokens': usage.get('completion_tokens', 0)
        }
        
        print(f"[OPENAI LLM RESPONSE] First 100 chars: {response_text[:100]}")
        print(f"[OPENAI LLM TOKENS] Prompt: {token_usage['prompt_tokens']}, Completion: {token_usage['completion_tokens']}")
        return response_text, token_usage
    
    def _get_language_instruction(self) -> str:
        """Get the language instruction for the LLM."""
        language_map = {
            'en': 'English',
            'fr': 'French',
            'es': 'Spanish',
            'de': 'German',
            'it': 'Italian',
            'pt': 'Portuguese',
            'nl': 'Dutch',
            'pl': 'Polish',
            'ru': 'Russian',
            'ja': 'Japanese',
            'zh': 'Chinese'
        }
        language_name = language_map.get(self.generation_language, 'English')
        return f"You are a helpful security analyst. IMPORTANT: You must respond ONLY in {language_name}. Every word, every sentence must be in {language_name}. Do not use English. Use only {language_name}.\n\n"
    
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
        
        # Ensure IOC has its ID for relation comparison
        ioc['id'] = ioc_id
        
        # Get relations
        relations = self._get_ioc_relations(ioc_id)
        
        # Build prompt
        prompt = self._build_ioc_prompt(ioc, relations)
        
        # Generate analysis
        analysis, token_usage = self._call_llm(prompt)
        
        return {
            'ioc_id': ioc_id,
            'ioc_value': ioc.get('value') or ioc.get('pattern', ''),
            'ioc_type': ioc.get('type', 'unknown'),
            'generated_at': datetime.utcnow().isoformat(),
            'token_usage': token_usage,
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
        
        # Get timeline and comments
        timeline = self._get_timeline_events(case_id=case_id)
        comments = self._get_comments('case', case_id)
        
        # Build prompt
        prompt = self._build_case_prompt(case, incidents, iocs, timeline, comments)
        
        # Generate report
        report, token_usage = self._call_llm(prompt)
        
        return {
            'case_id': case_id,
            'case_name': case.get('name') or case.get('title', 'Unknown'),
            'generated_at': datetime.utcnow().isoformat(),
            'token_usage': token_usage,
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
        
        # Get timeline and comments
        timeline = self._get_timeline_events(incident_id=incident_id)
        comments = self._get_comments('incident', incident_id)
        
        # Build prompt
        prompt = self._build_incident_prompt(incident, iocs, timeline, comments)
        
        # Generate analysis
        analysis, token_usage = self._call_llm(prompt)
        
        return {
            'incident_id': incident_id,
            'incident_name': incident.get('name') or incident.get('title', 'Unknown'),
            'generated_at': datetime.utcnow().isoformat(),
            'token_usage': token_usage,
            'analysis': analysis,
            'iocs_count': len(iocs)
        }
    
    def generate_checklist_report(self, checklist_id: str) -> Dict[str, Any]:
        """
        Generate a report for a checklist.
        
        Args:
            checklist_id: The checklist document ID
            
        Returns:
            Report data with checklist analysis
        """
        # Import here to avoid circular imports
        from app.services.checklist_service import ChecklistService
        
        checklist_service = ChecklistService()
        checklist = checklist_service.get_checklist(checklist_id)
        
        if not checklist:
            raise ValueError(f"Checklist {checklist_id} not found")
        
        # Build prompt for LLM analysis
        prompt = self._build_checklist_prompt(checklist)
        
        # Generate analysis
        analysis, token_usage = self._call_llm(prompt)
        
        return {
            'checklist_id': checklist_id,
            'checklist_title': checklist.get('title', 'Untitled Checklist'),
            'generated_at': datetime.utcnow().isoformat(),
            'token_usage': token_usage,
            'analysis': analysis,
            'items_count': len(checklist.get('items', []))
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
    
    def _get_timeline_events(self, case_id: str = None, incident_id: str = None) -> List[Dict]:
        """Get timeline events for a case or incident."""
        try:
            query = {'bool': {'should': [], 'minimum_should_match': 1}}
            
            if case_id:
                query['bool']['should'].append({'term': {'case_id': case_id}})
            if incident_id:
                query['bool']['should'].append({'term': {'incident_id': incident_id}})
            
            if not query['bool']['should']:
                return []
            
            result = self.es.search('timeline_events', {
                'query': query,
                'sort': [{'event_time': {'order': 'asc'}}],
                'size': 50
            })
            
            items = []
            for hit in result.get('hits', {}).get('hits', []):
                doc = hit['_source']
                doc['id'] = hit['_id']
                items.append(doc)
            return items
        except Exception:
            return []
    
    def _get_comments(self, entity_type: str, entity_id: str) -> List[Dict]:
        """Get comments for an entity (IOC, case, or incident)."""
        try:
            result = self.es.search('comments', {
                'query': {
                    'bool': {
                        'must': [
                            {'term': {'entity_type': entity_type}},
                            {'term': {'entity_id': entity_id}}
                        ],
                        'must_not': [
                            {'exists': {'field': 'parent_id'}}
                        ]
                    }
                },
                'sort': [{'created_at': {'order': 'asc'}}],
                'size': 50
            })
            
            items = []
            for hit in result.get('hits', {}).get('hits', []):
                doc = hit['_source']
                doc['id'] = hit['_id']
                items.append(doc)
            return items
        except Exception:
            return []
    
    def _build_detailed_relations_context(self, ioc: Dict, relations: List[Dict], max_relations: int = 15) -> str:
        """
        Build detailed context for related IOCs including their values and threat levels.
        This provides LLM with better context about WHY indicators are related.
        
        Args:
            ioc: The source IOC document
            relations: List of relation documents
            max_relations: Maximum number of relations to include
            
        Returns:
            Formatted string with detailed relation information
        """
        if not relations:
            return "No relations found"
        
        detailed_relations = []
        
        for idx, relation in enumerate(relations[:max_relations], 1):
            try:
                # Determine the target IOC ID
                source_id = relation.get('source_id')
                target_id = relation.get('target_id')
                ioc_id = ioc.get('id')
                
                # Get the OTHER IOC (the one that's not the main one)
                other_id = target_id if source_id == ioc_id else source_id
                
                # Fetch the related IOC to get its details
                related_ioc = self.ioc_service.get(other_id)
                if not related_ioc:
                    continue
                
                # Extract the related IOC value
                related_value = related_ioc.get('value') or related_ioc.get('pattern', 'Unknown')
                if related_value.startswith('[') and '=' in related_value:
                    related_value = related_value.split("'")[1] if "'" in related_value else related_value
                
                # Extract metadata
                relation_type = relation.get('relation_type', 'related')
                related_type = related_ioc.get('type', 'unknown')
                related_threat = related_ioc.get('x_metadata', {}).get('threat_level', related_ioc.get('severity', 'unknown'))
                related_description = related_ioc.get('description', 'No description available')
                
                # Get common attributes for explaining the connection
                common_tags = self._find_common_attributes(ioc, related_ioc)
                
                # Build a meaningful relationship description
                relation_explanation = self._build_relation_explanation(
                    relation_type, 
                    ioc.get('type'), 
                    related_type, 
                    common_tags
                )
                
                # Format the relation entry with clear structure
                # Make it very explicit what is relationship vs IOC type vs value
                relation_type_display = relation_type.replace('_', ' ').title()
                ioc_type_display = related_type if related_type != 'indicator' else 'Indicator'
                
                relation_entry = (
                    f"**Indicator #{idx}**:\n"
                    f"   Relationship: This IOC **{relation_type_display}** another indicator\n"
                    f"   Related IOC Type: {ioc_type_display}\n"
                    f"   Related IOC Value: {related_value}\n"
                    f"   Threat Level: {related_threat}\n"
                    f"   Details: {related_description[:150]}{'...' if len(related_description) > 150 else ''}\n"
                    f"   Connection Reason: {relation_explanation}"
                )
                
                detailed_relations.append(relation_entry)
            except Exception as e:
                # Fallback to simple format if detailed extraction fails
                continue
        
        if not detailed_relations:
            return "No relations found"
        
        return "\n\n".join(detailed_relations)
    
    def _find_common_attributes(self, ioc1: Dict, ioc2: Dict) -> List[str]:
        """
        Find common attributes between two IOCs to explain their connection.
        
        Args:
            ioc1: First IOC
            ioc2: Second IOC
            
        Returns:
            List of common attributes
        """
        common = []
        
        # Check for common sources
        sources1 = set(ioc1.get('x_metadata', {}).get('sources', ioc1.get('sources', [])))
        sources2 = set(ioc2.get('x_metadata', {}).get('sources', ioc2.get('sources', [])))
        if sources1 and sources2:
            common_sources = sources1 & sources2
            if common_sources:
                common.append(f"Both observed in sources: {', '.join(list(common_sources)[:2])}")
        
        # Check for common campaigns
        campaigns1 = set(ioc1.get('x_metadata', {}).get('campaigns', ioc1.get('campaigns', [])))
        campaigns2 = set(ioc2.get('x_metadata', {}).get('campaigns', ioc2.get('campaigns', [])))
        if campaigns1 and campaigns2:
            common_campaigns = campaigns1 & campaigns2
            if common_campaigns:
                common.append(f"Associated with campaign(s): {', '.join(list(common_campaigns)[:2])}")
        
        # Check for common labels/tags
        labels1 = set(ioc1.get('labels', []))
        labels2 = set(ioc2.get('labels', []))
        if labels1 and labels2:
            common_labels = labels1 & labels2
            if common_labels:
                common.append(f"Shared characteristics: {', '.join(list(common_labels)[:3])}")
        
        # Check same threat level
        threat1 = ioc1.get('x_metadata', {}).get('threat_level', ioc1.get('severity', ''))
        threat2 = ioc2.get('x_metadata', {}).get('threat_level', ioc2.get('severity', ''))
        if threat1 and threat1 == threat2:
            common.append(f"Same threat level: {threat1}")
        
        # Check temporal proximity (if timestamps exist)
        created1 = ioc1.get('created', ioc1.get('created_at', ''))
        created2 = ioc2.get('created', ioc2.get('created_at', ''))
        if created1 and created2:
            # Both discovered in same timeframe (within 7 days)
            from datetime import datetime, timedelta
            try:
                date1 = datetime.fromisoformat(created1.replace('Z', '+00:00'))
                date2 = datetime.fromisoformat(created2.replace('Z', '+00:00'))
                if abs((date1 - date2).days) <= 7:
                    common.append("Discovered in the same time period")
            except:
                pass
        
        return common if common else ["Detected together in security analysis"]
    
    def _build_relation_explanation(self, relation_type: str, type1: str, type2: str, common_attrs: List[str]) -> str:
        """
        Build a human-readable explanation of why two IOCs are related.
        
        Args:
            relation_type: Type of relationship (related, caused_by, used_by, etc.)
            type1: Type of first IOC
            type2: Type of second IOC
            common_attrs: List of common attributes
            
        Returns:
            Explanation string
        """
        # Start with common attributes
        if common_attrs:
            base_explanation = common_attrs[0]
        else:
            base_explanation = "Detected in the same security context"
        
        # Add relation-specific context
        relation_details = {
            'caused_by': f"This {type1} was likely caused by or is a consequence of the {type2}",
            'used_by': f"The {type2} uses or leverages the {type1} indicator",
            'implements': f"The {type2} implements or deploys the {type1}",
            'variant_of': f"This {type1} is a variant or derivative of the {type2}",
            'related': f"These indicators are related through common infrastructure, campaigns, or tactics"
        }
        
        additional_context = relation_details.get(relation_type, relation_details['related'])
        
        return f"{base_explanation}. {additional_context}"
    
    def _build_ioc_prompt(self, ioc: Dict, relations: List[Dict]) -> str:
        """Build prompt for IOC analysis."""
        # Get IOC value from either value field or extract from STIX pattern
        ioc_value = ioc.get('value') or ioc.get('pattern', '')
        if ioc_value.startswith('[') and '=' in ioc_value:
            # Extract value from STIX pattern like [file:hashes.SHA1 = '...']
            ioc_value = ioc_value.split("'")[1] if "'" in ioc_value else ioc_value
        
        # Build detailed relations context with actual IOC data
        relations_text = self._build_detailed_relations_context(ioc, relations, max_relations=15)
        
        # Use custom prompt if available
        if self.custom_prompt_ioc:
            try:
                language_instruction = self._get_language_instruction()
                custom_with_language = language_instruction + self.custom_prompt_ioc
                return custom_with_language.format(
                    type=ioc.get('type'),
                    value=ioc_value,
                    severity=ioc.get('x_metadata', {}).get('threat_level', ioc.get('severity', 'unknown')),
                    description=ioc.get('description', 'N/A'),
                    relations=relations_text
                )
            except KeyError:
                pass
        
        # Extract enriched metadata
        x_metadata = ioc.get('x_metadata', {})
        threat_level = x_metadata.get('threat_level', ioc.get('threat_level', 'unknown'))
        risk_score = x_metadata.get('risk_score', ioc.get('risk_score', 'N/A'))
        confidence = ioc.get('confidence', 'N/A')
        tlp = x_metadata.get('tlp', ioc.get('tlp', 'N/A'))
        
        # Get campaigns
        campaigns = x_metadata.get('campaigns', ioc.get('campaigns', []))
        campaigns_text = ', '.join(campaigns) if campaigns else 'No associated campaigns'
        
        # Get labels
        labels = ioc.get('labels', [])
        labels_text = ', '.join(labels) if labels else 'No labels'
        
        # Get indicator types
        indicator_types = ioc.get('indicator_types', [])
        indicator_types_text = ', '.join(indicator_types) if indicator_types else 'unknown'
        
        # Get external references
        external_refs = ioc.get('external_references', [])
        refs_text = ''
        if external_refs:
            refs_list = []
            for ref in external_refs:
                source = ref.get('source_name', 'Unknown source')
                url = ref.get('url', '')
                if url:
                    refs_list.append(f"- {source}: {url}")
                else:
                    refs_list.append(f"- {source}")
            refs_text = '\n'.join(refs_list)
        
        # Build a more detailed prompt that emphasizes relations
        relations_section = ""
        if relations:
            relations_section = f"""
## Analysis of Related Indicators

The following {len(relations)} indicators are directly related to this IOC. Each relationship provides important context:

{relations_text}

IMPORTANT: You MUST analyze each of the {len(relations)} related indicators listed above and explain:
- How each relationship type (e.g., exploits, based-on, communicates-with) affects the threat assessment
- Specific insights about the threat based on the related IOC values and their threat levels
- The combined threat picture when considering all related indicators together
"""
        
        language_instruction = self._get_language_instruction()
        return language_instruction + f"""Analyze this Indicator of Compromise (IOC) and provide a comprehensive threat assessment:

## IOC Details
- **Type**: {ioc.get('type')}
- **IOC Value**: {ioc_value}
- **IOC Categories**: {indicator_types_text}
- **Name**: {ioc.get('name', 'N/A')}

## Threat Assessment
- **Threat Level**: {threat_level}
- **Risk Score**: {risk_score}
- **Confidence**: {confidence}
- **TLP (Traffic Light Protocol)**: {tlp}

## Classification
- **Labels**: {labels_text}
- **Associated Campaigns**: {campaigns_text}

## Description
{ioc.get('description', 'No description available')}

## Additional Context
- **Created**: {ioc.get('created', ioc.get('created_at', 'Unknown'))}
- **Modified**: {ioc.get('modified', ioc.get('modified_at', 'Unknown'))}
- **Status**: {x_metadata.get('status', ioc.get('status', 'Active'))}
{f"- **External References**:" + chr(10) + refs_text if refs_text else ""}
{relations_section}

Please provide in **Markdown format**:
1. What this indicator represents and its role in potential attacks
2. Potential threats it indicates based on its type and severity
3. Analysis of how related indicators amplify or contextualize this threat (CRITICAL: mention each related indicator and how it connects)
4. Recommended mitigation and detection steps
5. Summary of the threat landscape based on the indicator network"""
    
    def _build_case_prompt(self, case: Dict, incidents: List[Dict], iocs: List[Dict], timeline: List[Dict] = None, comments: List[Dict] = None) -> str:
        """Build prompt for case analysis."""
        if timeline is None:
            timeline = []
        if comments is None:
            comments = []
        
        # Get language instruction
        language_instruction = self._get_language_instruction()
        
        # Format incident details with more info
        incidents_text = '\n'.join([
            f"- {i.get('title', i.get('name', 'Unknown'))}: {i.get('description', 'N/A')} (Type: {i.get('category', i.get('type', 'N/A'))})"
            for i in incidents[:5]
        ]) or "No incidents"
        
        # Format IOC details - handle STIX pattern format
        iocs_text = '\n'.join([
            f"- {i.get('type')}: {i.get('value') or i.get('pattern', 'N/A')} (Severity: {i.get('x_metadata', {}).get('threat_level', i.get('severity', 'N/A'))})"
            for i in iocs[:15]
        ]) or "No IOCs"
        
        # Format timeline events
        timeline_text = "No timeline events"
        if timeline:
            event_list = []
            for event in timeline[:15]:  # Limit to 15 events
                timestamp = event.get('event_time', event.get('timestamp', 'Unknown'))
                event_type = event.get('event_type', event.get('type', 'Event'))
                description = event.get('description', '')
                event_list.append(f"  - [{timestamp}] {event_type}: {description}")
            timeline_text = '\n'.join(event_list)
        
        # Format analyst comments
        comments_text = "No comments"
        if comments:
            comment_list = []
            for comment in comments[:10]:  # Limit to 10 comments
                author = comment.get('created_by_name', 'Unknown')
                created = comment.get('created_at', 'Unknown')
                content = comment.get('content', '')
                comment_list.append(f"  - [{created}] {author}: {content[:150]}{'...' if len(content) > 150 else ''}")
            comments_text = '\n'.join(comment_list)
        
        # Use custom prompt if available
        if self.custom_prompt_case:
            try:
                language_instruction = self._get_language_instruction()
                custom_with_language = language_instruction + self.custom_prompt_case
                return custom_with_language.format(
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
        
        # Extract additional metadata
        assigned_to = case.get('assigned_to', case.get('assignee', 'Unassigned'))
        created_at = case.get('created_at', 'Unknown')
        updated_at = case.get('updated_at', 'Unknown')
        severity = case.get('severity', 'Medium')
        
        # Build detailed incidents section with more context
        incidents_details = ""
        if incidents:
            incidents_details = "### Associated Incidents\n"
            for idx, incident in enumerate(incidents[:10], 1):
                incident_title = incident.get('title', incident.get('name', f'Incident {idx}'))
                incident_desc = incident.get('description', 'No description')
                incident_type = incident.get('category', incident.get('type', 'Unknown'))
                incident_severity = incident.get('severity', 'Unknown')
                incident_status = incident.get('status', 'Unknown')
                incidents_details += f"\n**{idx}. {incident_title}**\n"
                incidents_details += f"   - Type: {incident_type}\n"
                incidents_details += f"   - Severity: {incident_severity}\n"
                incidents_details += f"   - Status: {incident_status}\n"
                incidents_details += f"   - Details: {incident_desc[:200]}{'...' if len(incident_desc) > 200 else ''}\n"
        
        # Build detailed IOC section with more context
        iocs_details = ""
        if iocs:
            iocs_details = "### Associated Indicators of Compromise\n"
            for idx, ioc in enumerate(iocs[:15], 1):
                ioc_type = ioc.get('type', 'Unknown')
                ioc_value = ioc.get('value') or ioc.get('pattern', 'Unknown')
                if ioc_value.startswith('[') and '=' in ioc_value:
                    ioc_value = ioc_value.split("'")[1] if "'" in ioc_value else ioc_value
                threat_level = ioc.get('x_metadata', {}).get('threat_level', ioc.get('severity', 'Unknown'))
                ioc_desc = ioc.get('description', 'No description')
                ioc_status = ioc.get('x_metadata', {}).get('status', ioc.get('status', 'Active'))
                iocs_details += f"\n**{idx}. {ioc_type.upper()}: {ioc_value}**\n"
                iocs_details += f"   - Threat Level: {threat_level}\n"
                iocs_details += f"   - Status: {ioc_status}\n"
                iocs_details += f"   - Description: {ioc_desc[:150]}{'...' if len(ioc_desc) > 150 else ''}\n"
        
        # Build detailed timeline section
        timeline_details = ""
        if timeline:
            timeline_details = "### Detailed Timeline\n"
            for event in timeline[:20]:
                timestamp = event.get('event_time', event.get('timestamp', 'Unknown'))
                event_type = event.get('event_type', event.get('type', 'Event'))
                description = event.get('description', '')
                timeline_details += f"\n**[{timestamp}] {event_type}**\n"
                timeline_details += f"   {description}\n"
        
        # Build detailed comments section
        comments_details = ""
        if comments:
            comments_details = "### Analyst Observations\n"
            for comment in comments[:10]:
                author = comment.get('created_by_name', 'Unknown')
                created = comment.get('created_at', 'Unknown')
                content = comment.get('content', '')
                comments_details += f"\n**{author}** ({created}):\n"
                comments_details += f"{content}\n"
        
        return language_instruction + f"""# Security Case Investigation Report

Generate a comprehensive, detailed investigation report for this security case. Use ALL the provided data to create an in-depth analysis with specific references to the incidents, IOCs, timeline events, and analyst observations.

## Case Information

**Case Name:** {case.get('name', case.get('title', 'Unknown'))}
**Status:** {case.get('status')}
**Priority:** {case.get('priority')}
**Severity Level:** {severity}
**Assigned To:** {assigned_to}
**Created:** {created_at}
**Last Updated:** {updated_at}

## Case Description

{case.get('description', 'No detailed description provided')}

## Context and Scope

- **Number of Associated Incidents:** {len(incidents)}
- **Number of Indicators:** {len(iocs)}
- **Timeline Events:** {len(timeline)}
- **Analyst Comments:** {len(comments)}

{timeline_details if timeline_details else ""}

{incidents_details if incidents_details else ""}

{iocs_details if iocs_details else ""}

{comments_details if comments_details else ""}

## Report Requirements

Generate a professional security investigation report with the following sections. Format your response using plain markdown WITHOUT wrapping it in code blocks (no triple backticks).

### 1. Executive Summary
Provide a brief overview of the case, its significance, and key findings. Reference specific incidents and IOCs.

### 2. Incident Timeline
Reconstruct the sequence of events chronologically. Reference the timeline events provided above.

### 3. Threat Assessment
Based on the incidents and IOCs, assess the threat landscape. Include:
- The nature and scope of the threat
- Actor(s) involved (if identifiable)
- Attack methodology
- Specific threats posed by each incident and indicator

### 4. Compromised Assets and Impact
Detail what was impacted:
- Which systems/assets were affected
- The extent of compromise for each
- Business impact assessment

### 5. Technical Indicators Analysis
Analyze each IOC provided:
- Explain what each indicator represents
- Its role in the overall attack
- How indicators relate to specific incidents
- The threat significance of each

### 6. Investigation Findings
Synthesize the analyst observations and comments:
- Key discoveries from the investigation
- Evidence of specific attack techniques
- Patterns identified across incidents
- Correlation between different IOCs and incidents

### 7. Recommendations and Actions
Based on the complete investigation:
- Immediate containment actions needed
- Long-term remediation steps
- Detection rule recommendations
- Threat intelligence sharing recommendations
- Team responsibilities and next steps

### 8. Risk Assessment
- Current risk level (Critical/High/Medium/Low)
- Residual risks after recommended actions
- Timeline for remediation

**IMPORTANT:** This report must be specific, detailed, and reference actual data from the case, incidents, IOCs, timeline, and analyst comments provided. Avoid generic statements. Output plain formatted text, not a code block."""
    
    def _build_incident_prompt(self, incident: Dict, iocs: List[Dict], timeline: List[Dict] = None, comments: List[Dict] = None) -> str:
        """Build prompt for incident analysis."""
        if timeline is None:
            timeline = []
        if comments is None:
            comments = []
        
        # Get language instruction to add to default prompts
        language_instruction = self._get_language_instruction()
        
        # Format IOC details - handle STIX pattern format
        iocs_text = '\n'.join([
            f"- {i.get('type')}: {i.get('value') or i.get('pattern', 'N/A')} (Severity: {i.get('x_metadata', {}).get('threat_level', i.get('severity', 'N/A'))})"
            for i in iocs[:15]
        ]) or "No IOCs"
        
        # Use custom prompt if available
        if self.custom_prompt_incident:
            try:
                language_instruction = self._get_language_instruction()
                custom_with_language = language_instruction + self.custom_prompt_incident
                return custom_with_language.format(
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
        
        # Format timeline events
        timeline_text = "No timeline events"
        if timeline:
            event_list = []
            for event in timeline[:15]:  # Limit to 15 events
                timestamp = event.get('event_time', event.get('timestamp', 'Unknown'))
                event_type = event.get('event_type', event.get('type', 'Event'))
                description = event.get('description', '')
                event_list.append(f"  - [{timestamp}] {event_type}: {description}")
            timeline_text = '\n'.join(event_list)
        
        # Format comments from the comments parameter
        comments_text = "No analyst comments"
        if comments:
            comment_list = []
            for comment in comments[:10]:  # Limit to 10 comments
                author = comment.get('created_by_name', 'Unknown')
                created = comment.get('created_at', 'Unknown')
                content = comment.get('content', '')
                comment_list.append(f"  - [{created}] {author}: {content[:150]}{'...' if len(content) > 150 else ''}")
            if comment_list:
                comments_text = '\n'.join(comment_list)
        
        # Format MITRE tactics/techniques
        tactics_text = "No MITRE ATT&CK data"
        tactics = incident.get('mitre_tactics', incident.get('tactics', []))
        techniques = incident.get('mitre_techniques', incident.get('techniques', []))
        if tactics or techniques:
            tactics_lines = []
            if tactics:
                tactics_lines.append(f"  Tactics: {', '.join(tactics)}")
            if techniques:
                tactics_lines.append(f"  Techniques: {', '.join(techniques)}")
            tactics_text = '\n'.join(tactics_lines)
        
        return language_instruction + f"""Analyze this security incident and generate a comprehensive threat report:

## Incident Details
- **Incident Name**: {incident.get('title', incident.get('name', 'Unknown'))}
- **Type**: {incident.get('category', incident.get('type', 'Unknown'))}
- **Severity**: {incident.get('severity', 'Unknown')}
- **Status**: {incident.get('status')}

## Incident Description
{incident.get('description', 'No description provided')}

## Timeline of Events
{timeline_text}

## Analyst Comments and Observations
{comments_text}

## MITRE ATT&CK Mapping
{tactics_text}

## Incident Metadata
- **Created**: {incident.get('created_at', 'Unknown')}
- **Detected**: {incident.get('detected_at', 'Unknown')}
- **Resolved**: {incident.get('resolved_at', 'Not resolved')}

## Associated Indicators ({len(iocs)}):
{iocs_text}

Please provide in **Markdown format**:
1. Incident Summary (include key timeline events)
2. Attack Vector Analysis (include MITRE tactics/techniques)
3. Affected Systems and Assets
4. Indicators and their role in the incident
5. Key Analyst Observations (synthesize comments from the analyst comments section above)
6. Immediate Actions Required
7. Long-term Recommendations and Lessons Learned"""

    def _build_checklist_prompt(self, checklist: Dict) -> str:
        """Build prompt for checklist analysis."""
        title = checklist.get('title', 'Untitled Checklist')
        description = checklist.get('description', 'No description')
        items = checklist.get('items', [])
        created_by = checklist.get('created_by', 'Unknown')
        created_by_id = checklist.get('created_by_id', '')
        created_at = checklist.get('created_at', 'Unknown')
        assigned_to = checklist.get('assigned_to', '')
        assigned_to_name = checklist.get('assigned_to_name', 'Unassigned')
        
        # Get global tags, campaigns, cases, incidents and comments
        tags = checklist.get('tags', [])
        campaigns = checklist.get('campaigns', [])
        related_cases = checklist.get('related_cases', [])
        related_incidents = checklist.get('related_incidents', [])
        global_comments = checklist.get('comments', [])
        
        tags_text = ', '.join(tags) if tags else 'No tags assigned'
        campaigns_text = ', '.join(campaigns) if campaigns else 'No campaigns assigned'
        cases_text = ', '.join(related_cases) if related_cases else 'No related cases'
        incidents_text = ', '.join(related_incidents) if related_incidents else 'No related incidents'
        
        # Build global comments text
        global_comments_text = ""
        if global_comments:
            global_comments_text = "\n### Global Comments and Observations\n"
            for comment in global_comments:
                user = comment.get('user', 'Unknown')
                text = comment.get('text', '')
                timestamp = comment.get('created_at', '')
                global_comments_text += f"- **{user}** ({timestamp}): {text}\n"
        
        # Build items text - ONLY include completed items with detailed explanations
        items_text = ""
        completed_item_count = 0
        for item in items:
            # Only include completed items
            if not item.get('completed'):
                continue
            
            completed_item_count += 1
            item_title = item.get('title', 'Untitled Item')
            item_description = item.get('description', '')
            
            items_text += f"**{completed_item_count}. {item_title}**\n"
            
            # Add description if available
            if item_description:
                items_text += f"   - {item_description}\n"
            
            # Add comments as explanations of what was done
            comments = item.get('comments', [])
            if comments:
                items_text += "   - Actions and Details:\n"
                for comment in comments:
                    user = comment.get('user', 'Unknown')
                    text = comment.get('text', '')
                    items_text += f"     - {user}: {text}\n"
            
            items_text += "\n"
        
        # Use custom prompt if available
        if hasattr(self, 'custom_prompt_checklist') and self.custom_prompt_checklist:
            try:
                language_instruction = self._get_language_instruction()
                custom_with_language = language_instruction + self.custom_prompt_checklist
                return custom_with_language.format(
                    title=title,
                    description=description,
                    items=items_text,
                    tags=tags_text,
                    campaigns=campaigns_text,
                    related_cases=cases_text,
                    related_incidents=incidents_text,
                    assigned_to=assigned_to_name,
                    created_by=created_by,
                    global_comments=global_comments_text
                )
            except KeyError:
                pass
        
        # Get language instruction
        language_instruction = self._get_language_instruction()
        
        # Build contextual sections with proper fallbacks
        campaigns_context = campaigns_text if campaigns_text != "No campaigns assigned" else "General organizational security"
        cases_context = cases_text if cases_text != "No related cases" else "No direct case associations"
        incidents_context = incidents_text if incidents_text != "No related incidents" else "No direct incident associations"
        
        # Build global comments section
        global_comments_section = global_comments_text if global_comments_text else "No additional comments provided."
        
        return language_instruction + f"""# Work Report - {title}

## Overview

This report documents the work performed for the following security task checklist:

**Checklist**: {title}
**Description**: {description}
**Created By**: {created_by}
**Assigned To**: {assigned_to_name}
**Tags**: {tags_text}
**Related Campaigns**: {campaigns_text}
**Related Cases**: {cases_text}
**Related Incidents**: {incidents_text}

## Work Performed

The following work items have been successfully executed:

{items_text}

## Team Observations and Comments

{global_comments_section}

Please provide a detailed analysis in plain formatted text (NOT wrapped in code blocks). Include:

1. A detailed summary of all completed work items
2. The impact and importance of each completed action
3. How these completed items address the associated security concerns or campaigns
4. Key findings and discoveries from the completed work
5. Recommendations for follow-up or related security measures

IMPORTANT: Output plain text formatted with markdown - use headings, bullet points, bold text - but do NOT wrap the entire response in triple backticks or code blocks."""
