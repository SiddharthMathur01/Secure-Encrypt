import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime

# Create logs directory if it doesn't exist
LOGS_DIR = 'CyberSecurity\Secure-Encrypt\logs'
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

# Define log file paths
APP_LOG_FILE = os.path.join(LOGS_DIR, 'app.log')
SECURITY_LOG_FILE = os.path.join(LOGS_DIR, 'security.log')
ERROR_LOG_FILE = os.path.join(LOGS_DIR, 'error.log')

# Custom formatter with timestamp
class CustomFormatter(logging.Formatter):
    """Custom formatter with color codes for console output"""
    
    grey = "\x1b[38;21m"
    blue = "\x1b[38;5;39m"
    yellow = "\x1b[38;5;226m"
    red = "\x1b[38;5;196m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    
    format_str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    FORMATS = {
        logging.DEBUG: grey + format_str + reset,
        logging.INFO: blue + format_str + reset,
        logging.WARNING: yellow + format_str + reset,
        logging.ERROR: red + format_str + reset,
        logging.CRITICAL: bold_red + format_str + reset
    }
    
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)


def setup_logger(name, log_file, level=logging.INFO, console_output=True):
    """
    Set up a logger with file and optional console handlers
    
    Args:
        name: Logger name
        log_file: Path to log file
        level: Logging level
        console_output: Whether to output to console
    
    Returns:
        logging.Logger: Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # File handler with rotation (10MB max, keep 5 backup files)
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler (optional)
    if console_output:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(CustomFormatter())
        logger.addHandler(console_handler)
    
    return logger


def setup_security_logger():
    """Set up dedicated security logger for sensitive operations"""
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    
    if security_logger.handlers:
        return security_logger
    
    # Security logs go to separate file
    security_handler = RotatingFileHandler(
        SECURITY_LOG_FILE,
        maxBytes=10 * 1024 * 1024,
        backupCount=10,  # Keep more security logs
        encoding='utf-8'
    )
    security_handler.setLevel(logging.INFO)
    security_formatter = logging.Formatter(
        '%(asctime)s - SECURITY - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    security_handler.setFormatter(security_formatter)
    security_logger.addHandler(security_handler)
    
    return security_logger


# Create loggers
app_logger = setup_logger('app', APP_LOG_FILE, level=logging.INFO)
security_logger = setup_security_logger()
error_logger = setup_logger('error', ERROR_LOG_FILE, level=logging.ERROR, console_output=True)


def log_encryption_attempt(operation_type, file_type=None, file_size=None, success=True):
    """Log encryption operations"""
    if success:
        security_logger.info(
            f"Encryption successful - Type: {operation_type}, "
            f"FileType: {file_type or 'text'}, Size: {file_size or 'N/A'}"
        )
    else:
        security_logger.warning(
            f"Encryption failed - Type: {operation_type}, "
            f"FileType: {file_type or 'text'}"
        )


def log_decryption_attempt(operation_type, success=True, error_msg=None):
    """Log decryption operations"""
    if success:
        security_logger.info(f"Decryption successful - Type: {operation_type}")
    else:
        security_logger.warning(
            f"Decryption failed - Type: {operation_type}, Error: {error_msg or 'Unknown'}"
        )


def log_api_request(endpoint, method, status_code, ip_address=None):
    """Log API requests"""
    app_logger.info(
        f"API Request - Endpoint: {endpoint}, Method: {method}, "
        f"Status: {status_code}, IP: {ip_address or 'Unknown'}"
    )


def log_error(error_type, error_message, traceback_info=None):
    """Log errors with optional traceback"""
    error_logger.error(
        f"Error Type: {error_type}, Message: {error_message}"
    )
    if traceback_info:
        error_logger.error(f"Traceback: {traceback_info}")


def log_security_event(event_type, details):
    """Log security-related events"""
    security_logger.warning(f"Security Event - Type: {event_type}, Details: {details}")


# Export loggers
__all__ = [
    'app_logger',
    'security_logger', 
    'error_logger',
    'log_encryption_attempt',
    'log_decryption_attempt',
    'log_api_request',
    'log_error',
    'log_security_event'
]
