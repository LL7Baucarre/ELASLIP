import logging
import logging.handlers
import os
import time
import sys
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, NotFoundError
from app import create_app

# Ensure logs directory exists and set LOG_FILE so central logging uses it
log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(log_dir, exist_ok=True)
os.environ.setdefault('LOG_FILE', os.path.join(log_dir, 'app.log'))
os.environ.setdefault('LOG_LEVEL', os.getenv('LOG_LEVEL', 'DEBUG' if os.getenv('FLASK_ENV','development')=='development' else 'INFO'))

# Initialize basic logging configuration (uses env vars if needed)
from app.logging_config import init_logging
init_logging()
logger = logging.getLogger(__name__)

# Wait for Elasticsearch to be ready before creating app
def wait_for_elasticsearch(max_retries=30, retry_delay=2):
    """Wait for Elasticsearch to be fully ready"""
    from app.config import Config
    
    es_url = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')
    es_user = os.getenv('ELASTICSEARCH_USER', 'elastic')
    es_password = os.getenv('ELASTICSEARCH_PASSWORD', 'elastic123')
    
    # Add credentials to URL if not already present and URL doesn't contain @
    if es_user and es_password and '@' not in es_url:
        if es_url.startswith('https://'):
            es_url = es_url.replace('https://', f'https://{es_user}:{es_password}@')
        elif es_url.startswith('http://'):
            es_url = es_url.replace('http://', f'http://{es_user}:{es_password}@')
    
    retry_count = 0
    while retry_count < max_retries:
        try:
            # Create temporary ES client with SSL verification disabled
            es_temp = Elasticsearch([es_url], verify_certs=False, ssl_show_warn=False)
            
            # Try to get cluster health
            health = es_temp.cluster.health()
            
            # Check if cluster is at least yellow (ready to accept requests)
            if health.get('status') in ['yellow', 'green']:
                logger.info("Elasticsearch is ready (status: %s)", health.get('status'))
                es_temp.close()
                return True
            else:
                logger.info("Elasticsearch cluster status: %s, waiting...", health.get('status'))
                
        except (ConnectionError, Exception) as e:
            retry_count += 1
            if retry_count < max_retries:
                logger.warning("Waiting for Elasticsearch (%d/%d)... Error: %s", retry_count, max_retries, str(e)[:100])
                time.sleep(retry_delay)
            else:
                logger.error("Failed to connect to Elasticsearch after %d retries", max_retries)
                return False
    
    return False

# Ensure Elasticsearch is ready before starting app
if not wait_for_elasticsearch():
    logger.error("Elasticsearch did not become ready in time")
    sys.exit(1)

app = create_app()

if __name__ == '__main__':
    logger.info("Starting Flask app on 0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True, ssl_context='adhoc')
