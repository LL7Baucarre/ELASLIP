from app import create_app
app = create_app()
with app.app_context():
    from app.services.elasticsearch_service import ElasticsearchService
    es = ElasticsearchService()
    result = es.search('incidents', {'size': 1})
    if result['hits']['hits']:
        incident_id = result['hits']['hits'][0]['_id']
        print(f'Found incident ID: {incident_id}')
    else:
        print('No incidents found')
