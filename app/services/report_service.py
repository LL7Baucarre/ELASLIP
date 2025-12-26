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
        
        # Ensure IOC has its ID for relation comparison
        ioc['id'] = ioc_id
        
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
        
        # Get timeline and comments
        timeline = self._get_timeline_events(case_id=case_id)
        comments = self._get_comments('case', case_id)
        
        # Build prompt
        prompt = self._build_case_prompt(case, incidents, iocs, timeline, comments)
        
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
        
        # Get timeline and comments
        timeline = self._get_timeline_events(incident_id=incident_id)
        comments = self._get_comments('incident', incident_id)
        
        # Build prompt
        prompt = self._build_incident_prompt(incident, iocs, timeline, comments)
        
        # Generate analysis
        analysis = self._call_llm(prompt)
        
        return {
            'incident_id': incident_id,
            'incident_name': incident.get('name') or incident.get('title', 'Unknown'),
            'generated_at': datetime.utcnow().isoformat(),
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
        analysis = self._call_llm(prompt)
        
        return {
            'checklist_id': checklist_id,
            'checklist_title': checklist.get('title', 'Untitled Checklist'),
            'generated_at': datetime.utcnow().isoformat(),
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
                return self.custom_prompt_ioc.format(
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
                    refs_list.append(f"{source}: {url}")
                else:
                    refs_list.append(source)
            refs_text = '\n  - ' + '\n  - '.join(refs_list)
        
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
        
        return f"""Analyze this Indicator of Compromise (IOC) and provide a comprehensive threat assessment:

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
{f"- **External References**:{refs_text}" if refs_text else ""}
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
        
        # Extract additional metadata
        assigned_to = case.get('assigned_to', case.get('assignee', 'Unassigned'))
        created_at = case.get('created_at', 'Unknown')
        updated_at = case.get('updated_at', 'Unknown')
        severity = case.get('severity', 'Medium')
        
        return f"""Generate a comprehensive investigation report for this security case:

## Case Details
- **Case Name**: {case.get('name', case.get('title', 'Unknown'))}
- **Status**: {case.get('status')}
- **Priority**: {case.get('priority')}
- **Severity**: {severity}
- **Assigned To**: {assigned_to}

## Case Description
{case.get('description', 'No description provided')}

## Timeline of Events
{timeline_text}

## Analyst Comments and Observations
{comments_text}

## Case Metadata
- **Created**: {created_at}
- **Last Updated**: {updated_at}

## Associated Incidents ({len(incidents)}):
{incidents_text}

## Indicators of Compromise ({len(iocs)}):
{iocs_text}

Please provide in **Markdown format**:
1. Executive Summary
2. Timeline of Events (include timeline events from above)
3. Threat Assessment
4. Compromised Assets
5. Indicators and their significance
6. Person/Team in charge and responsibilities
7. Analyst Observations and Findings (synthesize comments)
8. Recommended Actions
9. Risk Level Assessment"""
    
    def _build_incident_prompt(self, incident: Dict, iocs: List[Dict], timeline: List[Dict] = None, comments: List[Dict] = None) -> str:
        """Build prompt for incident analysis."""
        if timeline is None:
            timeline = []
        if comments is None:
            comments = []
        
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
        
        return f"""Analyze this security incident and generate a comprehensive threat report:

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
        created_at = checklist.get('created_at', 'Unknown')
        
        # Count completed items
        completed_count = sum(1 for item in items if item.get('completed', False))
        total_items = len(items)
        completion_percentage = (completed_count / total_items * 100) if total_items > 0 else 0
        
        # Get global tags, campaigns, and comments
        tags = checklist.get('tags', [])
        campaigns = checklist.get('campaigns', [])
        global_comments = checklist.get('comments', [])
        
        tags_text = ', '.join(tags) if tags else 'No tags assigned'
        campaigns_text = ', '.join(campaigns) if campaigns else 'No campaigns assigned'
        
        # Build global comments text
        global_comments_text = ""
        if global_comments:
            global_comments_text = "\n### Global Comments and Observations\n"
            for comment in global_comments:
                user = comment.get('user', 'Unknown')
                text = comment.get('text', '')
                timestamp = comment.get('created_at', '')
                global_comments_text += f"- **{user}** ({timestamp}): {text}\n"
        
        # Build items text with detailed information
        items_text = ""
        for idx, item in enumerate(items, 1):
            status = "✓ COMPLETED" if item.get('completed') else "○ PENDING"
            item_title = item.get('title', 'Untitled Item')
            item_description = item.get('description', '')
            
            items_text += f"**{idx}. [{status}] {item_title}**\n"
            if item_description:
                items_text += f"   - Description: {item_description}\n"
            
            # Add comments if available
            comments = item.get('comments', [])
            if comments:
                items_text += "   - Comments:\n"
                for comment in comments:
                    user = comment.get('user', 'Unknown')
                    text = comment.get('text', '')
                    items_text += f"     - {user}: {text}\n"
            
            items_text += "\n"
        
        # Use custom prompt if available
        if hasattr(self, 'custom_prompt_checklist') and self.custom_prompt_checklist:
            try:
                return self.custom_prompt_checklist.format(
                    title=title,
                    description=description,
                    completed=completed_count,
                    total=total_items,
                    percentage=completion_percentage,
                    items=items_text,
                    tags=tags_text,
                    campaigns=campaigns_text,
                    global_comments=global_comments_text
                )
            except KeyError:
                pass
        
        # Build detailed default prompt for more comprehensive analysis
        context_info = ""
        if campaigns:
            context_info += f"\n\n### Campaign Context\nThis checklist is related to the following threat campaigns/APT groups: {campaigns_text}. Consider how the items and their status relate to the identified threats."
        
        return f"""# Detailed Checklist Analysis and Status Report

## Executive Overview

This report provides a comprehensive analysis of the checklist **"{title}"** and its current completion status.

## Checklist Metadata
- **Title**: {title}
- **Description**: {description}
- **Created By**: {created_by}
- **Created On**: {created_at}
- **Classification Tags**: {tags_text}
- **Associated Threat Campaigns**: {campaigns_text}
- **Overall Progress**: {completed_count} of {total_items} items completed ({completion_percentage:.1f}%)

## Current Status Overview

The checklist is currently **{completion_percentage:.1f}% complete** with **{completed_count}** items successfully completed and **{total_items - completed_count}** items still pending.

### Key Context from Stakeholders
{global_comments_text if global_comments_text else "No additional global comments provided."}

## Detailed Items Assessment

{items_text}

## Analysis Request

Please provide a comprehensive analysis report in **Markdown format** that includes:

1. **Executive Summary**: 
   - Overview of the checklist's purpose and strategic importance
   - Current completion status and trends
   - Key metrics and current progress indicators
   - Critical blockers or dependencies identified

2. **Contextual Threat Assessment**: 
   - How the checklist relates to the identified threat campaigns: {campaigns_text if campaigns_text != "No campaigns assigned" else "General organizational security"}
   - Risk implications of incomplete items in this context
   - Threat-specific recommendations based on campaigns

3. **Completion Progress Analysis**: 
   - Trend analysis of completion rates
   - Root causes of items still pending
   - Dependencies and blocking factors
   - Prioritization of remaining items based on criticality

4. **Impact Assessment**: 
   - Consequences of incomplete items on overall security posture
   - Evaluation of dependencies between items
   - Critical path analysis for remaining work
   - Business and operational impact

5. **Quality Review**:
   - Analysis of analyst comments and observations
   - Identification of items requiring rework or clarification
   - Assessment of completed work quality
   - Validation of completion criteria met

6. **Strategic Recommendations**:
   - Prioritized action plan for remaining items
   - Resource requirements and timeline estimates
   - Process improvements identified
   - Long-term preventive measures based on lessons learned

7. **Conclusion and Next Steps**: 
   - Summary of current status and key findings
   - Immediate actions required
   - Timeline for completion
   - Success criteria and validation methods{context_info}"""
