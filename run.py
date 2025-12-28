import logging
import logging.handlers
import os
from app import create_app
from app.config import Config

app = create_app()

# Configure logging
log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(log_dir, exist_ok=True)

# Get log level from config
log_level = getattr(logging, Config.LOG_LEVEL, logging.DEBUG)

# Set up file handler for all logs
file_handler = logging.handlers.RotatingFileHandler(
    os.path.join(log_dir, 'app.log'),
    maxBytes=10485760,  # 10MB
    backupCount=10
)
file_handler.setLevel(log_level)

# Set up console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(log_level)

# Create formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers to root logger
root_logger = logging.getLogger()
root_logger.setLevel(log_level)
root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)

# Configure app-specific loggers
app_module_logger = logging.getLogger('app')
app_module_logger.setLevel(log_level)
app_module_logger.addHandler(file_handler)
app_module_logger.addHandler(console_handler)

enrichment_logger = logging.getLogger('app.services.enrichment_service')
enrichment_logger.setLevel(log_level)
enrichment_logger.addHandler(file_handler)
enrichment_logger.addHandler(console_handler)

template_logger = logging.getLogger('app.models.api_template')
template_logger.setLevel(log_level)
template_logger.addHandler(file_handler)
template_logger.addHandler(console_handler)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
