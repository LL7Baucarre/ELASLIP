import logging
import logging.handlers
import os


def init_logging(config=None):
    """Initialise le logging de l'application à partir de la config fournie.

    Attendu: config.LOG_LEVEL (str), config.LOG_FILE (str)
    """
    log_level = getattr(config, 'LOG_LEVEL', os.getenv('LOG_LEVEL', 'INFO')).upper()
    log_file = getattr(config, 'LOG_FILE', os.getenv('LOG_FILE', 'app.log'))

    # Root logger
    root = logging.getLogger()
    root.setLevel(getattr(logging, log_level, logging.INFO))

    # Formatter
    fmt = logging.Formatter('%(asctime)s %(levelname)-8s %(name)s - %(message)s')

    # Console handler
    console = logging.StreamHandler()
    console.setLevel(getattr(logging, log_level, logging.INFO))
    console.setFormatter(fmt)

    # File handler (rotating)
    file_handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
    file_handler.setLevel(getattr(logging, log_level, logging.INFO))
    file_handler.setFormatter(fmt)

    # Remove existing handlers to avoid duplicate logs on re-init
    for h in list(root.handlers):
        root.removeHandler(h)

    root.addHandler(console)
    root.addHandler(file_handler)

    # Optional: set library log levels
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('elasticsearch').setLevel(logging.WARNING)

    return root
