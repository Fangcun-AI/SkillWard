import logging
from datetime import datetime
from pathlib import Path
from config import settings


def setup_logger():
    """Setup logger"""
    logger = logging.getLogger("skill-scanner")

    if logger.handlers:
        return logger

    log_dir = Path(settings.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    log_file = log_dir / f"skill_audit_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.setLevel(getattr(logging, settings.log_level.upper()))
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
