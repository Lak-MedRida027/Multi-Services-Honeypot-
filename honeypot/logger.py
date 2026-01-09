"""
logging system
"""
import logging
import sys
from pathlib import Path
from datetime import datetime

def setup_logging():
    # setup the place for logs
    current_file = Path(__file__).resolve()
    project_root = current_file.parent.parent

    log_dir = project_root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = log_dir / f"honeypot_logs_{timestamp}.log"
    
    # create logger
    logger = logging.getLogger("honeypot")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    
    # console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_format = logging.Formatter(
        '%(asctime)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # file handler
    try:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_format = logging.Formatter(
            '%(asctime)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    except IOError as e:
        logger.warning(f"could not open log file: {e}")
    
    return logger