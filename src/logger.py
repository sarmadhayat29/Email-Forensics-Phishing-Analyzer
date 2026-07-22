"""Centralised logging configuration for the Email Forensics Analyzer."""

import logging
import sys


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger for the given module name."""
    logger = logging.getLogger(name)

    # Avoid adding multiple handlers if the logger is already configured
    if not logger.hasHandlers():
        logger.setLevel(logging.INFO)

        # Console handler with standard formatting
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    return logger
