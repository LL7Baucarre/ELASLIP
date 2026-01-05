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
import logging
logger = logging.getLogger(__name__)


# Default prompt templates - Optimized for LLM generation
DEFAULT_PROMPT_STIX = """You are a senior threat intelligence analyst. Analyze the following STIX object (Indicator, Malware, Threat-Actor, etc.) and generate a professional threat assessment report.

## INPUT DATA

**🎯 MAIN STIX OBJECT (Primary Focus):**
- Type: {type}
- Value: {value}
- Threat Level: {severity}
- Description: {description}

**First-Level Relations (exactly like the STIX graph):**
{relations}

## YOUR TASK

Generate a comprehensive threat assessment in Markdown format. The MAIN STIX OBJECT is the primary focus, but you must analyze ALL first-level relations shown above.

### 1. Executive Summary
Write 2-3 sentences summarizing the MAIN STIX OBJECT, its threat significance, and its relationships with other entities.

### 2. Main STIX Object Threat Analysis (Primary Focus)
- What type of threat does this STIX object represent?
- What attack techniques or malware families is it associated with?
- What is the potential impact if this object is detected in an environment?

### 3. First-Level Relations Analysis (Important)
Analyze ALL related entities shown in the relations:
- **Related STIX Objects**: Explain how each related object connects to the main one and their role in the attack chain
- **Cases**: How is this STIX object connected to investigation cases? What does this reveal?
- **Incidents**: What security incidents involve this STIX object? What patterns emerge?

### 4. Attack Chain Reconstruction
Based on the main IOC and its relations, reconstruct the potential attack chain or threat scenario.

### 5. Detection & Response
- How to detect the main STIX object and its related indicators
- Immediate actions to take if detected
- Tools and techniques for investigation

### 6. Mitigation Recommendations
- Short-term containment actions
- Long-term remediation steps
- Prevention measures

## OUTPUT FORMAT
- Use Markdown formatting with headers, bullet points, and bold text
- Be specific and actionable
- Reference the actual STIX object values and ALL relations provided
- Give proper attention to each relation - they provide critical context
- Do NOT wrap the response in code blocks"""

DEFAULT_PROMPT_CASE = """You are a senior security incident response analyst. Generate a comprehensive investigation report for the following security case.

## CASE INFORMATION

**🎯 MAIN CASE (Primary Focus):**
- Name: {name}
- Status: {status}
- Priority: {priority}
- Severity: {severity}
- Assigned To: {assigned_to}
- Description: {description}

**Associated Data:**
- Incidents: {incidents_count}
- Indicators of Compromise: {iocs_count}

{timeline_details}

{incidents_details}

{iocs_details}

{comments_details}

## YOUR TASK

Generate a professional security investigation report. The CASE is the primary focus, but analyze ALL IOCs and their first-level relations shown in the IOC details section.

### 1. Executive Summary
Provide a 3-4 sentence overview of the case, key findings, current status, and the scope of related entities.

### 2. Timeline of Events
Reconstruct the attack timeline chronologically using the provided events. Include:
- Initial detection
- Key milestones
- Current state

### 3. Threat Assessment
- Nature and scope of the threat
- Attack methodology identified
- Threat actor assessment (if identifiable)

### 4. Technical Analysis
For each IOC in this case:
- Its role in the attack
- Its first-level relations (other IOCs, cases, incidents it connects to)
- How this reveals the broader attack pattern

### 5. Impact Assessment
- Affected systems and assets
- Business impact
- Data exposure risk

### 6. Investigation Findings
Synthesize analyst observations and key discoveries from the entire relation graph.

### 7. Recommendations
- Immediate containment actions
- Remediation steps
- Detection improvements
- Lessons learned

### 8. Risk Rating
Provide overall risk assessment (Critical/High/Medium/Low) with justification based on IOCs and their relations.

## OUTPUT FORMAT
- Use Markdown formatting
- Be specific and reference actual data from the case AND the IOC relations
- Provide actionable recommendations
- Do NOT wrap response in code blocks"""

DEFAULT_PROMPT_INCIDENT = """You are a security incident response specialist. Analyze the following security incident and generate a detailed incident report.

## INCIDENT DATA

**🎯 MAIN INCIDENT (Primary Focus):**
- Name: {name}
- Type: {type}
- Severity: {severity}
- Status: {status}
- Description: {description}

**Timeline:**
{timeline}

**Analyst Comments:**
{comments}

**MITRE ATT&CK:**
{tactics}

**Associated IOCs ({iocs_count}) with their first-level relations:**
{iocs}

## YOUR TASK

Generate a comprehensive incident report. The INCIDENT is the primary focus, but analyze ALL IOCs and their first-level relations (other IOCs, cases, incidents they connect to).

### 1. Incident Summary
Summarize the incident in 3-4 sentences: what happened, when, current status, and scope of related entities.

### 2. Attack Vector Analysis
- Initial access method
- Attack progression
- MITRE ATT&CK techniques used
- Attacker objectives

### 3. Affected Assets
- Systems compromised
- Data at risk
- Scope of impact

### 4. Indicators of Compromise with Relations
For each IOC:
- What it indicates
- Its role in the attack
- Its first-level relations (connected IOCs, cases, incidents)
- How these relations reveal the attack pattern
- Detection priority

### 5. Response Actions
- Actions already taken
- Recommended next steps
- Escalation requirements

### 6. Root Cause Analysis
What allowed this incident to occur and what can prevent recurrence.

### 7. Lessons Learned
Key takeaways and security improvements needed based on the full relation graph.

## OUTPUT FORMAT
- Use Markdown with headers and bullet points
- Be specific and actionable
- Reference actual incident data AND IOC relations
- Do NOT wrap response in code blocks"""

DEFAULT_PROMPT_CHECKLIST = """You are a security operations analyst. Generate a work completion report based on the following security checklist.

## CHECKLIST INFORMATION

**Title:** {name}
**Description:** {description}
**Created By:** {created_by}
**Assigned To:** {assigned_to}
**Tags:** {tags}
**Related Campaigns:** {campaigns}
**Related Cases:** {related_cases}
**Related Incidents:** {related_incidents}

**Completed Work Items:**
{items}

**Team Comments:**
{global_comments}

## YOUR TASK

Generate a professional work completion report with the following sections:

### 1. Executive Summary
Summarize what was accomplished, by whom, and the overall outcome.

### 2. Work Completed
For each completed item:
- What was done
- Why it was important
- Key outcomes or findings

### 3. Security Impact
- How this work improves security posture
- Risks mitigated
- Compliance improvements (if applicable)

### 4. Key Findings
Notable discoveries or issues identified during the work.

### 5. Recommendations
- Follow-up actions needed
- Additional security measures to consider
- Process improvements

### 6. Metrics
- Items completed vs total
- Time to completion
- Resources used

## OUTPUT FORMAT
- Use Markdown formatting
- Be clear and professional
- Reference actual work items and comments
- Do NOT wrap response in code blocks"""


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
            response = self.es.get('elaslip_app_config', 'llm_config')
            if response and response.get('found'):
                config = response.get('_source', {})
                self.llm_url = config.get('url', os.getenv('LLM_URL', 'http://ollama:11434')).rstrip('/')
                self.llm_model = config.get('model', os.getenv('LLM_MODEL', 'mistral'))
                self.llm_api_key = config.get('api_key', os.getenv('LLM_API_KEY', ''))
                self.llm_provider = config.get('provider', os.getenv('LLM_PROVIDER', 'auto'))  # auto, ollama, openai
                self.generation_language = config.get('generation_language', 'en')
                self.custom_prompt_stix = config.get('custom_prompt_stix', '')
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
        self.custom_prompt_stix = ''
        self.custom_prompt_case = ''
        self.custom_prompt_incident = ''
        self.custom_prompt_checklist = ''
    
    def is_configured(self) -> bool:
        """Check if LLM is properly configured."""
        # Check basic config first
        if not self.llm_url or not self.llm_model:
            return False
        
        provider = self._detect_llm_provider()
        try:
            if provider == 'openai':
                # Try OpenAI-compatible endpoint
                headers = {}
                if self.llm_api_key:
                    # Use API key in Authorization header
                    headers['Authorization'] = f'Bearer {self.llm_api_key}'
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
                # Use API key in Authorization header
                headers['Authorization'] = f'Bearer {self.llm_api_key}'
            response = requests.get(f"{self.llm_url}/v1/models", headers=headers, timeout=3)
            if response.status_code == 200:
                logger.info("[LLM DETECT] Detected OpenAI-compatible provider at %s", self.llm_url)
                return 'openai'
        except requests.RequestException:
            pass
        
        # Fall back to Ollama
        try:
            response = requests.get(f"{self.llm_url}/api/tags", timeout=3)
            if response.status_code == 200:
                logger.info("[LLM DETECT] Detected Ollama provider at %s", self.llm_url)
                return 'ollama'
        except requests.RequestException:
            pass
        
        # Default to OpenAI if URL contains 'openai' or v1/chat/completions pattern
        if 'openai' in self.llm_url or '/v1/' in self.llm_url:
            logger.info("[LLM DETECT] Detected OpenAI-compatible by URL pattern")
            return 'openai'
        
        # Default to Ollama
        logger.info("[LLM DETECT] Defaulting to Ollama provider")
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
            response = self.es.get('elaslip_app_config', 'llm_config')
            if response and response.get('found'):
                config = response.get('_source', {})
                old_lang = self.generation_language
                self.llm_url = config.get('url', os.getenv('LLM_URL', 'http://ollama:11434')).rstrip('/')
                self.llm_model = config.get('model', os.getenv('LLM_MODEL', 'mistral'))
                self.llm_api_key = config.get('api_key', os.getenv('LLM_API_KEY', ''))
                self.llm_provider = config.get('provider', os.getenv('LLM_PROVIDER', 'auto'))
                self.generation_language = config.get('generation_language', 'en')
                self.custom_prompt_stix = config.get('custom_prompt_stix', '')
                self.custom_prompt_case = config.get('custom_prompt_case', '')
                self.custom_prompt_incident = config.get('custom_prompt_incident', '')
                self.custom_prompt_checklist = config.get('custom_prompt_checklist', '')
                logger.info("[LLM CONFIG LOADED] Language: %s -> %s", old_lang, self.generation_language)
        except Exception as e:
            logger.exception("[LLM CONFIG ERROR] Failed to reload: %s", str(e))
        
        try:
            logger.debug("[LLM CALL] Using LLM URL: %s", self.llm_url)
            logger.debug("[LLM CALL] Generation language: %s", self.generation_language)
            
            # Detect provider
            provider = self._detect_llm_provider()
            logger.debug("[LLM CALL] Provider: %s, Model: %s, Language: %s", provider, self.llm_model, self.generation_language)
            
            if provider == 'openai':
                logger.debug("[LLM CALL] Calling OpenAI-compatible endpoint...")
                return self._call_openai_llm(prompt)
            else:
                logger.debug("[LLM CALL] Calling Ollama endpoint...")
                return self._call_ollama_llm(prompt)
        except requests.RequestException as e:
            logger.exception("[LLM ERROR] RequestException: %s", str(e))
            raise RuntimeError(f"Failed to call LLM: {str(e)}")
        except Exception as e:
            logger.exception("[LLM ERROR] General exception: %s: %s", type(e).__name__, str(e))
            raise
    
    def _call_ollama_llm(self, prompt: str) -> tuple:
        """Call Ollama API endpoint."""
        headers = {'Content-Type': 'application/json'}
        if self.llm_api_key:
            # Use API key in Authorization header (Ollama supports Bearer tokens)
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
        
        logger.debug("[LLM RESPONSE] First 100 chars: %s", response_text[:100])
        return response_text, token_usage
    
    def _call_openai_llm(self, prompt: str) -> tuple:
        """Call OpenAI-compatible API endpoint."""
        headers = {'Content-Type': 'application/json'}
        if self.llm_api_key:
            # Use API key in Authorization header
            headers['Authorization'] = f'Bearer {self.llm_api_key}'
        
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
        logger.debug("[OPENAI LLM] Posting to %s with model %s", request_url, self.llm_model)
        
        response = requests.post(
            request_url,
            json=payload,
            headers=headers,
            timeout=120
        )
        
        logger.debug("[OPENAI LLM] Response status: %s", response.status_code)
        response.raise_for_status()
        
        data = response.json()
        logger.debug("[OPENAI LLM] Response keys: %s", list(data.keys()))
        
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
        
        logger.debug("[OPENAI LLM RESPONSE] First 100 chars: %s", response_text[:100])
        logger.debug("[OPENAI LLM TOKENS] Prompt: %d, Completion: %d", token_usage.get('prompt_tokens', 0), token_usage.get('completion_tokens', 0))
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
        
        # Get ALL first-level relations (IOCs, cases, incidents) like the graph
        relations = self._get_first_level_relations(ioc_id)
        
        # Build prompt with emphasis on the main IOC
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
    
    def generate_stix_report(self, stix_id: str) -> Dict[str, Any]:
        """
        Generate a report for a STIX object and its relations.
        Works for all STIX types (indicator, malware, threat-actor, etc.).
        
        Args:
            stix_id: The STIX object ID
            
        Returns:
            Report data with analysis and relations
        """
        # Try to get the STIX object from both indices
        stix_obj = self._get_stix_object(stix_id)
        if not stix_obj:
            raise ValueError(f"STIX object {stix_id} not found")
        
        # Ensure object has its ID
        stix_obj['id'] = stix_id
        
        # Get ALL first-level relations (IOCs, cases, incidents) like the graph
        relations = self._get_first_level_relations(stix_id)
        
        # Build prompt - use IOC prompt format as it works well for all STIX types
        prompt = self._build_ioc_prompt(stix_obj, relations)
        
        # Generate analysis
        analysis, token_usage = self._call_llm(prompt)
        
        # Get display value for the object
        stix_value = stix_obj.get('value') or stix_obj.get('name') or stix_obj.get('pattern', stix_id)
        stix_type = stix_obj.get('type', 'unknown')
        
        return {
            'stix_id': stix_id,
            'stix_value': stix_value,
            'stix_type': stix_type,
            'generated_at': datetime.utcnow().isoformat(),
            'token_usage': token_usage,
            'analysis': analysis,
            'relations_count': len(relations.get('iocs', [])) + len(relations.get('cases', [])) + len(relations.get('incidents', []))
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
        
        # Get IOCs related to case WITH all their possible relations
        iocs = self._get_case_iocs_with_relations(case_id)
        
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
        
        # Get related IOCs WITH all their possible relations
        iocs = self._get_incident_iocs_with_relations(incident_id)
        
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
    
    def regenerate_ioc_report(self, ioc_id: str, correction_prompt: str, previous_report: str = '') -> Dict[str, Any]:
        """
        Regenerate an IOC report with correction instructions.
        
        Args:
            ioc_id: The IOC document ID
            correction_prompt: User correction/refinement instructions
            previous_report: The previous report content for context
            
        Returns:
            Report data with regenerated analysis
        """
        # Get IOC using the IOC service
        ioc = self.ioc_service.get(ioc_id)
        if not ioc:
            raise ValueError(f"IOC {ioc_id} not found")
        
        ioc['id'] = ioc_id
        relations = self._get_first_level_relations(ioc_id)
        
        # Build base prompt
        base_prompt = self._build_ioc_prompt(ioc, relations)
        
        # Build regeneration prompt
        prompt = self._build_regeneration_prompt(base_prompt, correction_prompt, previous_report)
        
        # Generate analysis
        analysis, token_usage = self._call_llm(prompt)
        
        return {
            'ioc_id': ioc_id,
            'ioc_value': ioc.get('value') or ioc.get('pattern', ''),
            'ioc_type': ioc.get('type', 'unknown'),
            'generated_at': datetime.utcnow().isoformat(),
            'token_usage': token_usage,
            'analysis': analysis,
            'relations_count': len(relations),
            'regenerated': True
        }
    
    def regenerate_stix_report(self, stix_id: str, correction_prompt: str, previous_report: str = '') -> Dict[str, Any]:
        """
        Regenerate a STIX object report with correction instructions.
        Works for all STIX types (indicator, malware, threat-actor, etc.).
        
        Args:
            stix_id: The STIX object ID
            correction_prompt: User correction/refinement instructions
            previous_report: The previous report content for context
            
        Returns:
            Report data with regenerated analysis
        """
        # Get STIX object from both indices
        stix_obj = self._get_stix_object(stix_id)
        if not stix_obj:
            raise ValueError(f"STIX object {stix_id} not found")
        
        stix_obj['id'] = stix_id
        relations = self._get_first_level_relations(stix_id)
        
        # Build base prompt
        base_prompt = self._build_ioc_prompt(stix_obj, relations)
        
        # Build regeneration prompt
        prompt = self._build_regeneration_prompt(base_prompt, correction_prompt, previous_report)
        
        # Generate analysis
        analysis, token_usage = self._call_llm(prompt)
        
        # Get display value
        stix_value = stix_obj.get('value') or stix_obj.get('name') or stix_obj.get('pattern', stix_id)
        stix_type = stix_obj.get('type', 'unknown')
        
        return {
            'stix_id': stix_id,
            'stix_value': stix_value,
            'stix_type': stix_type,
            'generated_at': datetime.utcnow().isoformat(),
            'token_usage': token_usage,
            'analysis': analysis,
            'relations_count': len(relations.get('iocs', [])) + len(relations.get('cases', [])) + len(relations.get('incidents', [])),
            'regenerated': True
        }
    
    def regenerate_case_report(self, case_id: str, correction_prompt: str, previous_report: str = '') -> Dict[str, Any]:
        """
        Regenerate a case report with correction instructions.
        
        Args:
            case_id: The case document ID
            correction_prompt: User correction/refinement instructions
            previous_report: The previous report content for context
            
        Returns:
            Report data with regenerated case summary
        """
        case = self.case_service.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        
        incidents = self._get_case_incidents(case_id)
        iocs = self._get_case_iocs_with_relations(case_id)
        timeline = self._get_timeline_events(case_id=case_id)
        comments = self._get_comments('case', case_id)
        
        # Build base prompt
        base_prompt = self._build_case_prompt(case, incidents, iocs, timeline, comments)
        
        # Build regeneration prompt
        prompt = self._build_regeneration_prompt(base_prompt, correction_prompt, previous_report)
        
        # Generate report
        report, token_usage = self._call_llm(prompt)
        
        return {
            'case_id': case_id,
            'case_name': case.get('name') or case.get('title', 'Unknown'),
            'generated_at': datetime.utcnow().isoformat(),
            'token_usage': token_usage,
            'report': report,
            'incidents_count': len(incidents),
            'iocs_count': len(iocs),
            'regenerated': True
        }
    
    def regenerate_incident_report(self, incident_id: str, correction_prompt: str, previous_report: str = '') -> Dict[str, Any]:
        """
        Regenerate an incident report with correction instructions.
        
        Args:
            incident_id: The incident document ID
            correction_prompt: User correction/refinement instructions
            previous_report: The previous report content for context
            
        Returns:
            Report data with regenerated incident analysis
        """
        incident = self.incident_service.get_incident(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        
        iocs = self._get_incident_iocs_with_relations(incident_id)
        timeline = self._get_timeline_events(incident_id=incident_id)
        comments = self._get_comments('incident', incident_id)
        
        # Build base prompt
        base_prompt = self._build_incident_prompt(incident, iocs, timeline, comments)
        
        # Build regeneration prompt
        prompt = self._build_regeneration_prompt(base_prompt, correction_prompt, previous_report)
        
        # Generate analysis
        analysis, token_usage = self._call_llm(prompt)
        
        return {
            'incident_id': incident_id,
            'incident_name': incident.get('name') or incident.get('title', 'Unknown'),
            'generated_at': datetime.utcnow().isoformat(),
            'token_usage': token_usage,
            'analysis': analysis,
            'iocs_count': len(iocs),
            'regenerated': True
        }
    
    def regenerate_checklist_report(self, checklist_id: str, correction_prompt: str, previous_report: str = '') -> Dict[str, Any]:
        """
        Regenerate a checklist report with correction instructions.
        
        Args:
            checklist_id: The checklist document ID
            correction_prompt: User correction/refinement instructions
            previous_report: The previous report content for context
            
        Returns:
            Report data with regenerated checklist analysis
        """
        from app.services.checklist_service import ChecklistService
        
        checklist_service = ChecklistService()
        checklist = checklist_service.get_checklist(checklist_id)
        
        if not checklist:
            raise ValueError(f"Checklist {checklist_id} not found")
        
        # Build base prompt
        base_prompt = self._build_checklist_prompt(checklist)
        
        # Build regeneration prompt
        prompt = self._build_regeneration_prompt(base_prompt, correction_prompt, previous_report)
        
        # Generate analysis
        analysis, token_usage = self._call_llm(prompt)
        
        return {
            'checklist_id': checklist_id,
            'checklist_title': checklist.get('title', 'Untitled Checklist'),
            'generated_at': datetime.utcnow().isoformat(),
            'token_usage': token_usage,
            'analysis': analysis,
            'items_count': len(checklist.get('items', [])),
            'regenerated': True
        }
    
    def _build_regeneration_prompt(self, base_prompt: str, correction_prompt: str, previous_report: str = '') -> str:
        """
        Build a prompt for regenerating a report with corrections.
        
        Args:
            base_prompt: The original prompt with all data
            correction_prompt: User correction/refinement instructions
            previous_report: The previous report for context (optional)
            
        Returns:
            Combined prompt for regeneration
        """
        language_instruction = self._get_language_instruction()
        
        regeneration_context = f"""{language_instruction}You are regenerating a security report based on user feedback.

## USER CORRECTION INSTRUCTIONS

The user has requested the following changes or refinements:

{correction_prompt}

"""
        
        if previous_report:
            regeneration_context += f"""## PREVIOUS REPORT

Here is the previous version of the report that needs to be improved:

{previous_report[:3000]}{'...[truncated]' if len(previous_report) > 3000 else ''}

"""
        
        regeneration_context += f"""## ORIGINAL DATA AND INSTRUCTIONS

{base_prompt}

## IMPORTANT

Apply the user correction instructions to generate an improved version of the report. 
Focus on addressing the specific feedback while maintaining the professional quality and structure.
Do NOT wrap the response in code blocks."""
        
        return regeneration_context

    def _get_ioc_relations(self, ioc_id: str) -> List[Dict]:
        """Get STIX 2.1 relationships for an IOC."""
        # Build source_ref (indicator--uuid format)
        source_ref = f"indicator--{ioc_id}" if not ioc_id.startswith('indicator--') else ioc_id
        
        query = {
            'query': {
                'bool': {
                    'should': [
                        {'term': {'source_ref': source_ref}},
                        {'term': {'target_ref': source_ref}}
                    ],
                    'minimum_should_match': 1
                }
            },
            'size': 100
        }
        result = self.es.search('stix_relationships', query)
        items = []
        for hit in result.get('hits', {}).get('hits', []):
            doc = hit['_source']
            doc['id'] = hit['_id']
            items.append(doc)
        return items
    
    def _get_first_level_relations(self, ioc_id: str) -> Dict[str, List[Dict]]:
        """
        Get ALL first-level relations for an IOC (exactly like the IOC graph):
        - Direct IOC-to-IOC relations
        - Cases containing this IOC
        - Incidents containing this IOC
        
        Args:
            ioc_id: The IOC document ID
            
        Returns:
            Dict with 'iocs', 'cases', 'incidents' keys containing relation lists
        """
        relations = {
            'iocs': [],
            'cases': [],
            'incidents': []
        }
        
        # 1. Get direct IOC-to-IOC relations (STIX 2.1 format)
        source_ref = f"indicator--{ioc_id}" if not ioc_id.startswith('indicator--') else ioc_id
        direct_ioc_relations = self._get_ioc_relations(ioc_id)
        for relation in direct_ioc_relations:
            rel_source_ref = relation.get('source_ref', '')
            rel_target_ref = relation.get('target_ref', '')
            # Get the OTHER IOC ref (already in indicator--uuid format)
            other_ref = rel_target_ref if rel_source_ref == source_ref else rel_source_ref
            # Use full indicator--uuid format as that's how IOCs are stored
            related_ioc_id = other_ref
            
            # Fetch the related IOC details
            try:
                related_ioc = self.ioc_service.get(related_ioc_id)
                if related_ioc:
                    related_ioc['id'] = related_ioc_id
                    related_ioc['_relation_type'] = relation.get('relationship_type', 'related-to')
                    relations['iocs'].append(related_ioc)
            except Exception:
                pass
        
        # 2. Get cases containing this IOC (same as graph)
        try:
            cases_result = self.es.search('cases', {
                'query': {'match_all': {}},
                'size': 1000
            })
            for hit in cases_result.get('hits', {}).get('hits', []):
                case_doc = hit['_source']
                ioc_ids = case_doc.get('ioc_ids', [])
                if ioc_id in ioc_ids:
                    case_doc['id'] = hit['_id']
                    case_doc['_relation_type'] = 'found-in-case'
                    relations['cases'].append(case_doc)
        except Exception:
            pass
        
        # 3. Get incidents containing this IOC (same as graph)
        try:
            incidents_result = self.es.search('incidents', {
                'query': {'match_all': {}},
                'size': 1000
            })
            for hit in incidents_result.get('hits', {}).get('hits', []):
                incident_doc = hit['_source']
                ioc_ids = incident_doc.get('ioc_ids', [])
                if ioc_id in ioc_ids:
                    incident_doc['id'] = hit['_id']
                    incident_doc['_relation_type'] = 'found-in-incident'
                    relations['incidents'].append(incident_doc)
        except Exception:
            pass
        
        return relations
    
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
    
    def _get_stix_object(self, stix_id: str) -> Optional[Dict]:
        """
        Get a STIX object from either the ioc or stix_objects index.
        Works for both indicators and other STIX types (malware, threat-actor, etc.).
        
        Args:
            stix_id: The STIX object ID
            
        Returns:
            The STIX object or None if not found
        """
        # Try to get from IOC index first (indicators)
        try:
            ioc = self.ioc_service.get(stix_id)
            if ioc:
                return ioc
        except Exception:
            pass
        
        # Try to get from STIX objects index (malware, threat-actor, etc.)
        try:
            from app.services.stix_service import STIXService
            stix_obj = STIXService.get_sdo(stix_id)
            if stix_obj:
                # Normalize fields for consistent formatting
                if 'value' not in stix_obj and 'pattern' in stix_obj:
                    stix_obj['value'] = stix_obj['pattern']
                if 'value' not in stix_obj and 'name' in stix_obj:
                    stix_obj['value'] = stix_obj['name']
                return stix_obj
        except Exception:
            pass
        
        return None
    
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
    
    def _get_case_iocs_with_relations(self, case_id: str) -> List[Dict]:
        """
        Get IOCs for a case WITH all their possible relations included.
        For each IOC, includes:
        - Direct IOC-to-IOC relations
        - Transitive relations
        - Cases and incidents containing the IOC
        """
        # Get case document first
        case = self.case_service.get_case(case_id)
        if not case:
            return []
        
        ioc_ids = case.get('ioc_ids', [])
        if not ioc_ids:
            return []
        
        # Fetch each IOC with all its first-level relations
        items = []
        for ioc_id in ioc_ids[:20]:  # Limit to 20
            try:
                ioc = self._get_stix_object(ioc_id)
                if ioc:
                    ioc['id'] = ioc_id
                    # Include first-level relations for this IOC (like the graph)
                    ioc['_first_level_relations'] = self._get_first_level_relations(ioc_id)
                    items.append(ioc)
            except Exception:
                pass
        return items
    
    def _get_incident_iocs_with_relations(self, incident_id: str) -> List[Dict]:
        """
        Get IOCs for an incident WITH all their first-level relations included.
        For each IOC, includes (exactly like the graph):
        - Direct IOC-to-IOC relations
        - Cases containing the IOC
        - Incidents containing the IOC
        """
        # Get incident document first
        incident = self.incident_service.get_incident(incident_id)
        if not incident:
            return []
        
        ioc_ids = incident.get('ioc_ids', [])
        if not ioc_ids:
            return []
        
        # Fetch each IOC with all its first-level relations
        items = []
        for ioc_id in ioc_ids[:20]:  # Limit to 20
            try:
                ioc = self._get_stix_object(ioc_id)
                if ioc:
                    ioc['id'] = ioc_id
                    # Include first-level relations for this IOC (like the graph)
                    ioc['_first_level_relations'] = self._get_first_level_relations(ioc_id)
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
                # Check if this is a container entity (case or incident)
                if relation.get('_relation_type') in ['contained_in_case', 'contained_in_incident']:
                    entity_type = 'Case' if relation.get('_relation_type') == 'contained_in_case' else 'Incident'
                    entity_name = relation.get('name') or relation.get('title', 'Unknown')
                    entity_desc = relation.get('description', 'No description')
                    relation_entry = (
                        f"**{entity_type} #{idx}**:\n"
                        f"   Type: {entity_type}\n"
                        f"   Name: {entity_name}\n"
                        f"   Description: {entity_desc[:150]}{'...' if len(entity_desc) > 150 else ''}\n"
                        f"   Connection Reason: This IOC is directly involved in this {entity_type.lower()}"
                    )
                    detailed_relations.append(relation_entry)
                    continue
                
                # Handle IOC-to-IOC relations (STIX 2.1 format)
                # Determine the target IOC ref
                rel_source_ref = relation.get('source_ref', '')
                rel_target_ref = relation.get('target_ref', '')
                ioc_id = ioc.get('id')
                ioc_ref = f"indicator--{ioc_id}" if not ioc_id.startswith('indicator--') else ioc_id
                
                # Get the OTHER IOC (the one that's not the main one)
                other_ref = rel_target_ref if rel_source_ref == ioc_ref else rel_source_ref
                # Use full indicator--uuid format as that's how IOCs are stored
                other_id = other_ref
                
                # Fetch the related IOC to get its details
                related_ioc = self.ioc_service.get(other_id)
                if not related_ioc:
                    continue
                
                # Extract the related IOC value
                related_value = related_ioc.get('value') or related_ioc.get('pattern', 'Unknown')
                if related_value.startswith('[') and '=' in related_value:
                    related_value = related_value.split("'")[1] if "'" in related_value else related_value
                
                # Extract metadata
                relation_type = relation.get('relationship_type', 'related-to')
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
                
                # Get relations of the related IOC itself to show threat chain
                related_ioc_relations = self._get_ioc_relations(other_id)
                related_ioc_context = ""
                other_ref_for_secondary = f"indicator--{other_id}" if not other_id.startswith('indicator--') else other_id
                ioc_ref_for_secondary = f"indicator--{ioc.get('id')}" if not ioc.get('id', '').startswith('indicator--') else ioc.get('id')
                
                if related_ioc_relations:
                    # Filter out back-references to the main IOC
                    secondary_relations = []
                    for rel in related_ioc_relations[:3]:  # Limit to 3 secondary relations
                        rel_source_ref = rel.get('source_ref', '')
                        rel_target_ref = rel.get('target_ref', '')
                        
                        # Skip if this relation just points back to main IOC
                        if rel_source_ref == ioc_ref_for_secondary or rel_target_ref == ioc_ref_for_secondary:
                            continue
                        
                        # Get the OTHER IOC in this secondary relation
                        sec_other_ref = rel_target_ref if rel_source_ref == other_ref_for_secondary else rel_source_ref
                        # Use full indicator--uuid format as that's how IOCs are stored
                        sec_other_id = sec_other_ref
                        secondary_ioc = self.ioc_service.get(sec_other_id)
                        
                        if secondary_ioc:
                            sec_value = secondary_ioc.get('value') or secondary_ioc.get('pattern', 'Unknown')
                            if sec_value.startswith('[') and '=' in sec_value:
                                sec_value = sec_value.split("'")[1] if "'" in sec_value else sec_value
                            
                            sec_threat = secondary_ioc.get('x_metadata', {}).get('threat_level', secondary_ioc.get('severity', 'unknown'))
                            rel_type_display = rel.get('relationship_type', 'related-to').replace('_', ' ').replace('-', ' ').title()
                            secondary_relations.append(f"- This indicator **{rel_type_display}** {sec_value} (Threat: {sec_threat})")
                    
                    if secondary_relations:
                        related_ioc_context = "\n   Related Connections of this Indicator:\n   " + "\n   ".join(secondary_relations)
                
                relation_entry = (
                    f"**Indicator #{idx}**:\n"
                    f"   Relationship: This IOC **{relation_type_display}** another indicator\n"
                    f"   Related IOC Type: {ioc_type_display}\n"
                    f"   Related IOC Value: {related_value}\n"
                    f"   Threat Level: {related_threat}\n"
                    f"   Details: {related_description[:150]}{'...' if len(related_description) > 150 else ''}\n"
                    f"   Connection Reason: {relation_explanation}{related_ioc_context}"
                )
                
                detailed_relations.append(relation_entry)
            except Exception as e:
                # Fallback to simple format if detailed extraction fails
                continue
        
        if not detailed_relations:
            return "No relations found"
        
        return "\n\n".join(detailed_relations)
    
    def _build_first_level_relations_context(self, main_ioc: Dict, relations: Dict[str, List[Dict]]) -> str:
        """
        Build detailed context for first-level relations (exactly like the graph).
        
        Args:
            main_ioc: The main IOC document
            relations: Dict with 'iocs', 'cases', 'incidents' keys
            
        Returns:
            Formatted string with detailed relation information
        """
        sections = []
        
        # 1. Related IOCs section
        related_iocs = relations.get('iocs', [])
        if related_iocs:
            ioc_section = "### Related IOCs (Direct first-level connections)\n"
            for idx, ioc in enumerate(related_iocs[:15], 1):
                ioc_value = ioc.get('value') or ioc.get('ioc_value') or ioc.get('pattern', 'Unknown')
                if ioc_value.startswith('[') and '=' in ioc_value:
                    ioc_value = ioc_value.split("'")[1] if "'" in ioc_value else ioc_value
                ioc_type = ioc.get('type') or ioc.get('ioc_type', 'Unknown')
                threat_level = ioc.get('x_metadata', {}).get('threat_level', ioc.get('threat_level', 'Unknown'))
                relation_type = ioc.get('_relation_type', 'related-to').replace('_', ' ').replace('-', ' ').title()
                description = ioc.get('description', 'No description')[:100]
                
                ioc_section += f"""
**{idx}. {ioc_type.upper()}: {ioc_value}**
   - Relationship: **{relation_type}**
   - Threat Level: {threat_level}
   - Description: {description}{'...' if len(description) >= 100 else ''}
"""
            sections.append(ioc_section)
        
        # 2. Cases containing this IOC
        cases = relations.get('cases', [])
        if cases:
            case_section = "### Cases Containing This IOC\n"
            for idx, case in enumerate(cases[:10], 1):
                case_title = case.get('title') or case.get('name', 'Unknown Case')
                case_status = case.get('status', 'Unknown')
                case_severity = case.get('severity', 'Unknown')
                case_desc = case.get('description', 'No description')[:100]
                
                case_section += f"""
**{idx}. Case: {case_title}**
   - Status: {case_status}
   - Severity: {case_severity}
   - Description: {case_desc}{'...' if len(case_desc) >= 100 else ''}
"""
            sections.append(case_section)
        
        # 3. Incidents containing this IOC
        incidents = relations.get('incidents', [])
        if incidents:
            incident_section = "### Incidents Containing This IOC\n"
            for idx, incident in enumerate(incidents[:10], 1):
                incident_title = incident.get('title') or incident.get('name', 'Unknown Incident')
                incident_status = incident.get('status', 'Unknown')
                incident_severity = incident.get('severity', 'Unknown')
                incident_desc = incident.get('description', 'No description')[:100]
                
                incident_section += f"""
**{idx}. Incident: {incident_title}**
   - Status: {incident_status}
   - Severity: {incident_severity}
   - Description: {incident_desc}{'...' if len(incident_desc) >= 100 else ''}
"""
            sections.append(incident_section)
        
        if not sections:
            return "No first-level relations found for this IOC."
        
        return "\n".join(sections)
    
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
        
        # Helper function to safely convert sources to a set of strings
        def get_sources_set(ioc):
            try:
                sources = ioc.get('x_metadata', {}).get('sources', ioc.get('sources', []))
                if isinstance(sources, list):
                    # Filter out dict items, convert rest to strings
                    return set(str(s) if not isinstance(s, dict) else s.get('name', '') for s in sources if s and (not isinstance(s, dict) or s.get('name')))
                elif isinstance(sources, dict):
                    return set(sources.keys()) if sources else set()
                return set()
            except:
                return set()
        
        # Check for common sources
        sources1 = get_sources_set(ioc1)
        sources2 = get_sources_set(ioc2)
        if sources1 and sources2:
            common_sources = sources1 & sources2
            if common_sources:
                common.append(f"Both observed in sources: {', '.join(list(common_sources)[:2])}")
        
        # Helper function to safely convert campaigns to a set
        def get_campaigns_set(ioc):
            try:
                campaigns = ioc.get('x_metadata', {}).get('campaigns', ioc.get('campaigns', []))
                if isinstance(campaigns, list):
                    return set(str(c) if not isinstance(c, dict) else c.get('name', '') for c in campaigns if c and (not isinstance(c, dict) or c.get('name')))
                elif isinstance(campaigns, dict):
                    return set(campaigns.keys()) if campaigns else set()
                return set()
            except:
                return set()
        
        # Check for common campaigns
        campaigns1 = get_campaigns_set(ioc1)
        campaigns2 = get_campaigns_set(ioc2)
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
    
    def _build_ioc_prompt(self, ioc: Dict, relations: Dict[str, List[Dict]]) -> str:
        """
        Build prompt for IOC analysis with emphasis on the main IOC.
        
        Args:
            ioc: The main IOC document
            relations: Dict with 'iocs', 'cases', 'incidents' keys (from _get_first_level_relations)
        """
        # Get IOC value from either value field or extract from STIX pattern
        ioc_value = ioc.get('value') or ioc.get('pattern', '')
        if ioc_value.startswith('[') and '=' in ioc_value:
            # Extract value from STIX pattern like [file:hashes.SHA1 = '...']
            ioc_value = ioc_value.split("'")[1] if "'" in ioc_value else ioc_value
        
        # Build detailed relations context with the new structure
        relations_text = self._build_first_level_relations_context(ioc, relations)
        
        # Calculate totals
        total_iocs = len(relations.get('iocs', []))
        total_cases = len(relations.get('cases', []))
        total_incidents = len(relations.get('incidents', []))
        total_relations = total_iocs + total_cases + total_incidents
        
        # Use custom prompt if available
        if self.custom_prompt_stix:
            try:
                language_instruction = self._get_language_instruction()
                custom_with_language = language_instruction + self.custom_prompt_stix
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
        
        # Build a more detailed prompt that emphasizes the MAIN IOC and all first-level relations
        relations_section = ""
        if total_relations > 0:
            relations_section = f"""
## ALL First-Level Relations (exactly like the graph visualization)

This IOC has **{total_relations} first-level connections**:
- **{total_iocs}** related IOCs
- **{total_cases}** cases containing this IOC  
- **{total_incidents}** incidents containing this IOC

{relations_text}

**CRITICAL ANALYSIS INSTRUCTIONS:**
1. This report is about the **MAIN IOC: {ioc_value}** - it must be the PRIMARY FOCUS
2. Analyze how EACH of the {total_relations} related entities connect to the main IOC
3. For related IOCs: explain the relationship type and combined threat
4. For cases: explain what the IOC role is in the investigation
5. For incidents: explain how this IOC contributed to the security event
"""
        
        language_instruction = self._get_language_instruction()
        return language_instruction + f"""# Threat Assessment Report: {ioc_value}

**THIS REPORT FOCUSES ON THE MAIN IOC BELOW. All related entities provide context.**

## 🎯 MAIN IOC Details (Primary Focus)
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

## Report Requirements

Generate a comprehensive threat assessment with **emphasis on the MAIN IOC**:

1. **Executive Summary** - What does {ioc_value} represent? Why is it important?
2. **Threat Analysis** - Detailed analysis of this specific IOC
3. **Related Entities Analysis** - How each related IOC/case/incident connects to the main IOC
4. **Attack Chain Context** - How this IOC fits in potential attack scenarios
5. **Detection & Response** - How to detect and respond to this specific IOC
6. **Mitigation Recommendations** - Actions specific to this threat"""
    
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
        
        # Build detailed IOC section with more context and ALL their first-level relations
        iocs_details = ""
        if iocs:
            iocs_details = "### Associated Indicators of Compromise (with first-level relations like the graph)\n"
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
                
                # Add first-level relations for this IOC (exactly like the graph)
                first_level_rels = ioc.get('_first_level_relations', {})
                related_iocs = first_level_rels.get('iocs', [])
                related_cases = first_level_rels.get('cases', [])
                related_incidents = first_level_rels.get('incidents', [])
                total_rels = len(related_iocs) + len(related_cases) + len(related_incidents)
                
                if total_rels > 0:
                    iocs_details += f"   - **First-Level Relations**: {total_rels} entities ({len(related_iocs)} IOCs, {len(related_cases)} cases, {len(related_incidents)} incidents)\n"
                    
                    # Show related IOCs
                    for rel_ioc in related_iocs[:3]:
                        rel_value = rel_ioc.get('value') or rel_ioc.get('ioc_value') or rel_ioc.get('pattern', 'Unknown')
                        if rel_value.startswith('[') and '=' in rel_value:
                            rel_value = rel_value.split("'")[1] if "'" in rel_value else rel_value
                        rel_type = rel_ioc.get('_relation_type', 'related').replace('-', ' ')
                        iocs_details += f"      - IOC ({rel_type}): {rel_value}\n"
                    
                    # Show related cases
                    for rel_case in related_cases[:2]:
                        case_name = rel_case.get('title') or rel_case.get('name', 'Unknown')
                        iocs_details += f"      - Case: {case_name}\n"
                    
                    # Show related incidents  
                    for rel_incident in related_incidents[:2]:
                        incident_name = rel_incident.get('title') or rel_incident.get('name', 'Unknown')
                        iocs_details += f"      - Incident: {incident_name}\n"
        
        # Build detailed timeline section with rich content
        timeline_details = ""
        if timeline:
            timeline_details = "### Detailed Timeline\n"
            timeline_details += self._build_detailed_timeline_context(timeline, max_events=20)
        
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
    
    
    def _build_detailed_timeline_context(self, timeline: List[Dict], max_events: int = 15) -> str:
        """
        Build detailed context for timeline events including titles and content.
        
        Args:
            timeline: List of timeline event documents
            max_events: Maximum number of events to include
            
        Returns:
            Formatted string with detailed timeline information
        """
        if not timeline:
            return "No timeline events"
        
        detailed_events = []
        
        for idx, event in enumerate(timeline[:max_events], 1):
            try:
                # Extract event details
                timestamp = event.get('event_time', event.get('timestamp', 'Unknown'))
                event_type = event.get('event_type', event.get('type', 'Event'))
                title = event.get('title', '')
                content = event.get('content', '')
                description = event.get('description', '')
                created_by = event.get('created_by_name', 'Unknown')
                
                # Prefer title and content over description for richer details
                event_details = title or description or 'No details provided'
                
                # Extract key information from content if available
                content_summary = ""
                if content and len(content) > 50:
                    # Try to extract first paragraph or key line from content
                    lines = content.split('\n')
                    # Skip markdown headers and find actual content
                    for line in lines:
                        if line.strip() and not line.startswith('#'):
                            content_summary = line.strip()
                            break
                    if not content_summary and lines:
                        content_summary = lines[0].strip()
                
                # Format the event entry with clear hierarchy
                event_type_display = event_type.replace('_', ' ').title()
                
                event_entry = (
                    f"**Event #{idx}**: [{timestamp}]\n"
                    f"   Type: {event_type_display}\n"
                    f"   Title: {event_details[:100]}{'...' if len(event_details) > 100 else ''}\n"
                    f"   Analyst: {created_by}"
                )
                
                # Add content summary if available
                if content_summary:
                    event_entry += f"\n   Details: {content_summary[:150]}{'...' if len(content_summary) > 150 else ''}"
                
                detailed_events.append(event_entry)
                
            except Exception:
                # Fallback to simple format if detailed extraction fails
                continue
        
        if not detailed_events:
            return "No timeline events with details"
        
        return "\n\n".join(detailed_events)
    
    def _build_incident_prompt(self, incident: Dict, iocs: List[Dict], timeline: List[Dict] = None, comments: List[Dict] = None) -> str:
        """Build prompt for incident analysis."""
        if timeline is None:
            timeline = []
        if comments is None:
            comments = []
        
        # Get language instruction to add to default prompts
        language_instruction = self._get_language_instruction()
        
        # Build detailed IOC section with all their relations
        iocs_details = ""
        if iocs:
            iocs_details = "\n## Detailed Indicators of Compromise (with first-level relations like the graph)\n"
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
                
                # Add first-level relations for this IOC (exactly like the graph)
                first_level_rels = ioc.get('_first_level_relations', {})
                related_iocs = first_level_rels.get('iocs', [])
                related_cases = first_level_rels.get('cases', [])
                related_incidents = first_level_rels.get('incidents', [])
                total_rels = len(related_iocs) + len(related_cases) + len(related_incidents)
                
                if total_rels > 0:
                    iocs_details += f"   - **First-Level Relations**: {total_rels} entities ({len(related_iocs)} IOCs, {len(related_cases)} cases, {len(related_incidents)} incidents)\n"
                    
                    # Show related IOCs
                    for rel_ioc in related_iocs[:3]:
                        rel_value = rel_ioc.get('value') or rel_ioc.get('ioc_value') or rel_ioc.get('pattern', 'Unknown')
                        if rel_value.startswith('[') and '=' in rel_value:
                            rel_value = rel_value.split("'")[1] if "'" in rel_value else rel_value
                        rel_type = rel_ioc.get('_relation_type', 'related').replace('-', ' ')
                        iocs_details += f"      - IOC ({rel_type}): {rel_value}\n"
                    
                    # Show related cases
                    for rel_case in related_cases[:2]:
                        case_name = rel_case.get('title') or rel_case.get('name', 'Unknown')
                        iocs_details += f"      - Case: {case_name}\n"
                    
                    # Show related incidents  
                    for rel_incident in related_incidents[:2]:
                        incident_name = rel_incident.get('title') or rel_incident.get('name', 'Unknown')
                        iocs_details += f"      - Incident: {incident_name}\n"
        
        # Format IOC details - handle STIX pattern format (for simple list)
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
        
        # Format timeline events with rich details
        timeline_text = "No timeline events"
        if timeline:
            timeline_text = self._build_detailed_timeline_context(timeline, max_events=15)
        
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

{iocs_details if iocs_details else "## Associated Indicators: No IOCs"}

Please provide in **Markdown format**:
1. Incident Summary (include key timeline events)
2. Attack Vector Analysis (include MITRE tactics/techniques)
3. Affected Systems and Assets
4. Indicators and their role in the incident (include all related IOCs and their connections)
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
        
        # Resolve incident IDs to names
        incidents_text = ''
        if related_incidents:
            incident_names = []
            for incident_id in related_incidents:
                try:
                    incident = self.incident_service.get_incident(incident_id)
                    if incident:
                        incident_name = incident.get('title', incident_id)
                        incident_names.append(incident_name)
                    else:
                        incident_names.append(incident_id)
                except Exception:
                    incident_names.append(incident_id)
            incidents_text = ', '.join(incident_names)
        else:
            incidents_text = 'No related incidents'
        
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

IMPORTANT: Output plain text formatted with markdown - use headings, bullet points, bold text - but do NOT wrap the entire response in code blocks."""
