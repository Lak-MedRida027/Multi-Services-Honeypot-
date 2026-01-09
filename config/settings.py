"""
Configuration settings for the honeypot system
"""
import os
from datetime import datetime

# Base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Logging configuration
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = "logs/honeypot.log"

# Create log directory if it doesn't exist
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# SSH Configuration
SSH_PORT = 2222
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

# HTTP Configuration
HTTP_DEFAULT_PORT = 8080
DEFAULT_SERVICE = "wordpress"

# MySQL Configuration
MYSQL_PORT = 3306
MYSQL_VERSION = "8.0.29"

# RDP Configuration
RDP_PORT = 3389
RDP_OS_VERSION = "Windows Server 2019"