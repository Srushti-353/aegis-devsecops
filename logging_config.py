import logging
import sys


def configure_logging() -> logging.Logger:
    logger = logging.getLogger("AEGIS")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    logger.propagate = False
    return logger


LOGGER = configure_logging()


def log_event(event: str, **details: object) -> None:
    message = event
    if details:
        safe_details = {key: value for key, value in details.items() if "KEY" not in key.upper() and "TOKEN" not in key.upper() and "SECRET" not in key.upper()}
        if safe_details:
            message += " | " + ", ".join(f"{k}={v}" for k, v in safe_details.items())
    LOGGER.info(message)
