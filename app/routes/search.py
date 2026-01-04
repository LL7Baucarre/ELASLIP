"""Search API Routes."""

from flask import Blueprint, request, jsonify
import logging

from app.auth import login_or_api_key_required
from app.services.elasticsearch_service import ElasticsearchService
from app.services.enrichment_service import EnrichmentService
from app.services.stix_service import STIXService
from app.utils.pattern_generator import PatternGenerator
from app.utils.request_helpers import get_pagination_params, parse_comma_separated_list

search_bp = Blueprint('search', __name__)
es_service = ElasticsearchService()
logger = logging.getLogger(__name__)


@search_bp.route('', methods=['GET', 'POST'])
@login_or_api_key_required
def search_iocs():
    """
    Search across all entities (IOCs, Cases, Incidents, Users).
    ---
    tags:
      - Search
    summary: Search for IOCs
    parameters:
      - in: query
        name: q
        schema:
          type: string
        description: Search query (searches in pattern and value fields)
      - in: query
        name: type
        schema:
          type: string
          enum: [md5, sha1, sha256, ipv4, ipv6, domain, email, url, asn, file-path, process-name, registry-key, windows-registry-key, mutex, certificate-serial]
        description: Filter by IOC type
      - in: query
        name: labels
        schema:
          type: string
        description: Comma-separated labels to filter
      - in: query
        name: source
        schema:
          type: string
        description: Filter by source name
      - in: query
        name: page
        schema:
          type: integer
          default: 1
        description: Page number
      - in: query
        name: per_page
        schema:
          type: integer
          default: 20
          maximum: 100
        description: Items per page
      - in: query
        name: enrich
        schema:
          type: boolean
          default: false
        description: Also query external APIs for enrichment
    responses:
      200:
        description: Search results
        schema:
          type: object
          properties:
            items:
              type: array
              items:
                type: object
            results:
              type: array
              items:
                type: object
            total:
              type: integer
            page:
              type: integer
            per_page:
              type: integer
    """
    if request.method == 'POST':
        data = request.get_json() or {}
    else:
        data = request.args.to_dict()
    
    query_text = data.get('query', data.get('q', ''))
    ioc_type = data.get('type')
    source = data.get('source')
    from_date = data.get('from_date')
    to_date = data.get('to_date')
    enrich = data.get('enrich', 'false').lower() == 'true' if isinstance(data.get('enrich'), str) else bool(data.get('enrich'))
    
    page, per_page = get_pagination_params(default_per_page=20)
    
    # Handle labels
    labels = data.get('labels')
    if isinstance(labels, str):
        labels = [l.strip() for l in labels.split(',') if l.strip()]
    
    # Execute multi-index search
    es = ElasticsearchService()
    from_idx = (page - 1) * per_page
    
    items = []
    total = 0
    
    logger.debug(f"Search query: {query_text}")
    
    # Search in STIX Objects
    stix_query = {"bool": {"must": [], "filter": []}}
    if query_text:
        stix_query["bool"]["must"].append({
            "multi_match": {
                "query": query_text,
                "fields": ["name", "description", "pattern", "value", "type"],
                "type": "best_fields"
            }
        })
    if ioc_type:
        stix_query["bool"]["filter"].append({"term": {"type": ioc_type.lower()}})
    if labels:
        for label in labels:
            stix_query["bool"]["filter"].append({"term": {"labels": label}})
    if source:
        stix_query["bool"]["filter"].append({
            "nested": {
                "path": "external_references",
                "query": {"term": {"external_references.source_name": source}}
            }
        })
    if from_date or to_date:
        date_range = {"range": {"created": {}}}
        if from_date:
            date_range["range"]["created"]["gte"] = from_date
        if to_date:
            date_range["range"]["created"]["lte"] = to_date
        stix_query["bool"]["filter"].append(date_range)
    
    if not stix_query["bool"]["must"] and not stix_query["bool"]["filter"]:
        stix_query = {"match_all": {}}
    
    try:
        stix_result = es.search('stix_objects', {
            "query": stix_query,
            "from": from_idx,
            "size": per_page,
            "sort": [{"created": {"order": "desc"}}]
        })
        
        for hit in stix_result['hits']['hits']:
            doc = hit['_source']
            doc['id'] = hit['_id']
            doc['entity_type'] = 'stix'
            items.append(doc)
        
        stix_total = stix_result['hits']['total']['value']
        total += stix_total
        logger.debug(f"STIX search found {stix_total} results")
    except Exception as e:
        logger.error(f"STIX search error: {str(e)}")
        stix_total = 0
    
    # Search in Cases
    if query_text:
        cases_query = {
            "multi_match": {
                "query": query_text,
                "fields": ["title", "description"],
                "type": "best_fields"
            }
        }
        
        try:
            cases_result = es.search('cases', {
                "query": cases_query,
                "from": from_idx,
                "size": per_page,
                "sort": [{"created_at": {"order": "desc"}}]
            })
            
            cases_found = 0
            for hit in cases_result['hits']['hits']:
                doc = hit['_source']
                doc['id'] = hit['_id']
                doc['entity_type'] = 'case'
                doc['name'] = doc.get('title', '')
                items.append(doc)
                cases_found += 1
            
            cases_total = cases_result['hits']['total']['value']
            total += cases_total
            logger.debug(f"Cases search found {cases_total} results")
        except Exception as e:
            logger.error(f"Cases search error: {str(e)}", exc_info=True)
    
    # Search in Incidents
    if query_text:
        incidents_query = {
            "multi_match": {
                "query": query_text,
                "fields": ["title", "description"],
                "type": "best_fields"
            }
        }
        
        try:
            incidents_result = es.search('incidents', {
                "query": incidents_query,
                "from": from_idx,
                "size": per_page,
                "sort": [{"created_at": {"order": "desc"}}]
            })
            
            incidents_found = 0
            for hit in incidents_result['hits']['hits']:
                doc = hit['_source']
                doc['id'] = hit['_id']
                doc['entity_type'] = 'incident'
                doc['name'] = doc.get('title', '')
                items.append(doc)
                incidents_found += 1
            
            incidents_total = incidents_result['hits']['total']['value']
            total += incidents_total
            logger.debug(f"Incidents search found {incidents_total} results")
        except Exception as e:
            logger.error(f"Incidents search error: {str(e)}", exc_info=True)
    
    # Search in Users - DISABLED
    # if query_text:
    #     # Use wildcard since username/email are keyword fields (non-analyzed)
    #     users_query = {
    #         "bool": {
    #             "should": [
    #                 {"wildcard": {"username": f"*{query_text.lower()}*"}},
    #                 {"wildcard": {"email": f"*{query_text.lower()}*"}}
    #             ],
    #             "minimum_should_match": 1
    #         }
    #     }
    #     
    #     try:
    #         users_result = es.search('users', {
    #             "query": users_query,
    #             "from": 0,
    #             "size": per_page,
    #             "sort": [{"created_at": {"order": "desc"}}]
    #         })
    #         
    #         users_found = 0
    #         for hit in users_result['hits']['hits']:
    #             doc = hit['_source']
    #             doc['id'] = hit['_id']
    #             doc['entity_type'] = 'user'
    #             doc['name'] = doc.get('username', '')
    #             doc['title'] = f"User: {doc.get('username', '')}"
    #             items.append(doc)
    #             users_found += 1
    #         
    #         users_total = users_result['hits']['total']['value']
    #         total += users_total
    #         logger.debug(f"Users search found {users_total} results")
    #     except Exception as e:
    #         logger.error(f"Users search error: {str(e)}", exc_info=True)
    
    logger.info(f"Total search results: {total}, items returned: {len(items)}")
    
    response = {
        'query': query_text,
        'items': items,
        'results': items,  # Alias for frontend compatibility
        'total': total,
        'page': page,
        'per_page': per_page
    }
    
    # Enrich results if requested
    if enrich and query_text:
        try:
            enrichment = EnrichmentService()
            response['enrichment'] = enrichment.enrich_value(query_text)
        except Exception as e:
            response['enrichment_error'] = str(e)
    
    return jsonify(response)


@search_bp.route('/quick', methods=['GET'])
@login_or_api_key_required  
def quick_search():
    """
    Quick search - auto-detect IOC type and search.
    
    Query parameters:
    - q: The value to search for
    - enrich: If true, also query external APIs
    """
    query = request.args.get('q', '').strip()
    enrich = request.args.get('enrich', 'false').lower() == 'true'
    
    if not query:
        return jsonify({'error': 'Query parameter q is required'}), 400
    
    # Auto-detect type
    detected_type = PatternGenerator.detect_type(query)
    
    result = {
        'query': query,
        'detected_type': detected_type,
        'items': [],
        'total': 0
    }
    
    # Search by exact value
    es = ElasticsearchService()
    
    search_queries = [
        {"match": {"pattern": query}},
        {"match": {"name": query}},
        {"match": {"value": query}}
    ]
    
    # Also generate and search by pattern if type is detected
    if detected_type:
        try:
            pattern = PatternGenerator.generate_pattern(detected_type, query)
            search_queries.append({"match": {"pattern": pattern}})
        except ValueError:
            pass
    
    es_result = es.search('stix_objects', {
        "query": {
            "bool": {
                "should": search_queries,
                "minimum_should_match": 1
            }
        },
        "size": 50
    })
    
    for hit in es_result['hits']['hits']:
        doc = hit['_source']
        doc['id'] = hit['_id']
        result['items'].append(doc)
    
    result['total'] = es_result['hits']['total']['value']
    
    # Enrich if requested
    if enrich:
        try:
            enrichment = EnrichmentService()
            result['enrichment'] = enrichment.enrich_value(query, detected_type)
        except Exception as e:
            result['enrichment_error'] = str(e)
    
    return jsonify(result)


@search_bp.route('/advanced', methods=['POST'])
@login_or_api_key_required
def advanced_search():
    """
    Advanced search with raw Elasticsearch query DSL.
    
    Expected JSON body:
    {
        "query": { ... Elasticsearch query DSL ... },
        "size": 20,
        "from": 0,
        "sort": [ ... ]
    }
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    # Limit size
    if 'size' in data:
        data['size'] = min(int(data['size']), 100)
    else:
        data['size'] = 20
    
    es = ElasticsearchService()
    
    try:
        result = es.search('stix_objects', data)
        
        items = []
        for hit in result['hits']['hits']:
            doc = hit['_source']
            doc['id'] = hit['_id']
            doc['_score'] = hit.get('_score')
            items.append(doc)
        
        return jsonify({
            'items': items,
            'total': result['hits']['total']['value'],
            'aggregations': result.get('aggregations')
        })
    
    except Exception as e:
        return jsonify({'error': f'Search error: {str(e)}'}), 400


@search_bp.route('/iocs', methods=['GET'])
@search_bp.route('/stix', methods=['GET'])
@login_or_api_key_required
def search_stix_api():
    """
    Search for STIX objects - for linking/autocomplete.
    
    Query parameters:
    - q: Query string to search
    - size: Number of results (default: 10)
    - type: STIX type filter (optional)
    """
    query = request.args.get('q', '').strip()
    size = request.args.get('size', 10, type=int)
    stix_type = request.args.get('type', '').strip()
    
    if not query:
        return jsonify({'items': [], 'total': 0}), 200
    
    try:
        # Build search query - same format as main search
        es_query = {"bool": {"must": [], "filter": []}}
        
        es_query["bool"]["must"].append({
            "multi_match": {
                "query": query,
                "fields": ["name", "pattern", "value", "description"],
                "type": "best_fields"
            }
        })
        
        if stix_type:
            es_query["bool"]["filter"].append({"term": {"type": stix_type.lower()}})
        
        if not es_query["bool"]["must"] and not es_query["bool"]["filter"]:
            es_query = {"match_all": {}}
        
        es_result = es_service.search('stix_objects', {
            "query": es_query,
            "size": min(size, 100),
            "_source": ["name", "type", "pattern", "value", "description", "labels"]
        })
        
        items = []
        for doc in es_result['hits']['hits']:
            item = doc['_source']
            item['id'] = doc['_id']
            items.append(item)
        
        return jsonify({
            'items': items,
            'total': es_result['hits']['total']['value']
        })
    
    except Exception as e:
        return jsonify({'error': f'Search error: {str(e)}'}), 400
