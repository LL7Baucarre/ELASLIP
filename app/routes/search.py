"""Search API Routes."""

from flask import Blueprint, request, jsonify

from app.auth import login_or_api_key_required
from app.services.elasticsearch_service import ElasticsearchService
from app.services.enrichment_service import EnrichmentService
from app.utils.pattern_generator import PatternGenerator

search_bp = Blueprint('search', __name__)
es_service = ElasticsearchService()


@search_bp.route('', methods=['GET', 'POST'])
@login_or_api_key_required
def search_iocs():
    """
    Search for IOCs.
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
    page = int(data.get('page', 1))
    per_page = min(int(data.get('per_page', 20)), 100)
    enrich = data.get('enrich', 'false').lower() == 'true' if isinstance(data.get('enrich'), str) else bool(data.get('enrich'))
    
    # Handle labels
    labels = data.get('labels')
    if isinstance(labels, str):
        labels = [l.strip() for l in labels.split(',') if l.strip()]
    
    # Build Elasticsearch query
    es_query = {"bool": {"must": [], "filter": []}}
    
    if query_text:
        # Search in pattern field
        es_query["bool"]["must"].append({
            "multi_match": {
                "query": query_text,
                "fields": ["pattern", "pattern.keyword", "ioc_value", "name", "description"],
                "type": "best_fields"
            }
        })
    
    if ioc_type:
        es_query["bool"]["filter"].append({"term": {"ioc_type": ioc_type.lower()}})
    
    if labels:
        for label in labels:
            es_query["bool"]["filter"].append({"term": {"labels": label}})
    
    if source:
        es_query["bool"]["filter"].append({
            "nested": {
                "path": "sources",
                "query": {"term": {"sources.name": source}}
            }
        })
    
    if from_date or to_date:
        date_range = {"range": {"created": {}}}
        if from_date:
            date_range["range"]["created"]["gte"] = from_date
        if to_date:
            date_range["range"]["created"]["lte"] = to_date
        es_query["bool"]["filter"].append(date_range)
    
    # If no conditions, match all
    if not es_query["bool"]["must"] and not es_query["bool"]["filter"]:
        es_query = {"match_all": {}}
    
    # Execute search
    es = ElasticsearchService()
    from_idx = (page - 1) * per_page
    
    result = es.search('ioc', {
        "query": es_query,
        "from": from_idx,
        "size": per_page,
        "sort": [{"created": {"order": "desc"}}],
        "highlight": {
            "fields": {
                "pattern": {},
                "name": {},
                "description": {}
            }
        }
    })
    
    items = []
    for hit in result['hits']['hits']:
        doc = hit['_source']
        doc['id'] = hit['_id']
        if 'highlight' in hit:
            doc['_highlight'] = hit['highlight']
        
        # Add compatibility aliases for frontend
        if 'ioc_value' in doc and 'value' not in doc:
            doc['value'] = doc['ioc_value']
        if 'ioc_type' in doc and 'type' not in doc:
            doc['type'] = doc['ioc_type']
        
        items.append(doc)
    
    response = {
        'query': query_text,
        'items': items,
        'results': items,  # Alias for frontend compatibility
        'total': result['hits']['total']['value'],
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
        {"term": {"ioc_value": query.lower() if detected_type in ['md5', 'sha1', 'sha256'] else query}}
    ]
    
    # Also generate and search by pattern if type is detected
    if detected_type:
        try:
            pattern = PatternGenerator.generate_pattern(detected_type, query)
            search_queries.append({"match": {"pattern": pattern}})
        except ValueError:
            pass
    
    es_result = es.search('ioc', {
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
        result = es.search('ioc', data)
        
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
@login_or_api_key_required
def search_iocs_api():
    """
    Search for IOCs - for linking/autocomplete.
    
    Query parameters:
    - q: Query string to search
    - size: Number of results (default: 10)
    - type: IOC type filter (optional)
    """
    query = request.args.get('q', '').strip()
    size = request.args.get('size', 10, type=int)
    ioc_type = request.args.get('type', '').strip()
    
    if not query:
        return jsonify({'items': [], 'total': 0}), 200
    
    try:
        # Build search query - same format as main search
        es_query = {"bool": {"must": [], "filter": []}}
        
        es_query["bool"]["must"].append({
            "multi_match": {
                "query": query,
                "fields": ["pattern", "pattern.keyword", "ioc_value", "name", "value"],
                "type": "best_fields"
            }
        })
        
        if ioc_type:
            es_query["bool"]["filter"].append({"term": {"ioc_type": ioc_type.lower()}})
        
        if not es_query["bool"]["must"] and not es_query["bool"]["filter"]:
            es_query = {"match_all": {}}
        
        es_result = es_service.search('ioc', {
            "query": es_query,
            "size": min(size, 100),
            "_source": ["ioc_value", "value", "ioc_type", "type", "pattern", "name", "source", "sources"]
        })
        
        items = []
        for doc in es_result['hits']['hits']:
            item = doc['_source']
            item['id'] = doc['_id']
            
            # Add compatibility fields
            if 'ioc_value' in item and 'value' not in item:
                item['value'] = item['ioc_value']
            if 'ioc_type' in item and 'type' not in item:
                item['type'] = item['ioc_type']
            
            items.append(item)
        
        return jsonify({
            'items': items,
            'total': es_result['hits']['total']['value']
        })
    
    except Exception as e:
        return jsonify({'error': f'Search error: {str(e)}'}), 400
