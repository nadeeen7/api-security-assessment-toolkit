"""Log operational counts, never requests, credentials or bodies."""
import logging

def get_logger():
    logger = logging.getLogger("api_toolkit")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger
