"""
Configuration Manager
=====================
Loads application settings from environment variables and .env files.
Uses python-dotenv to keep secrets out of source code.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file (if it exists)
# This should be called once when the application starts.
load_dotenv()


def get_config(key: str, default: str = None) -> str:
    """
    Get a configuration value from environment variables.

    Args:
        key: The environment variable name (e.g., "OPENAI_API_KEY").
        default: Default value if the variable is not set.

    Returns:
        The configuration value as a string.
    """
    return os.getenv(key, default)


# ============================================
# Application-wide settings
# ============================================

# Log level for the application
LOG_LEVEL = get_config("LOG_LEVEL", "INFO")

# Project version
PROJECT_VERSION = "0.1.0"

# Project name
PROJECT_NAME = "CyberTrace"
