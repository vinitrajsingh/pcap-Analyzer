import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent.absolute()

# Upload configuration
UPLOAD_FOLDER = BASE_DIR / 'uploads'
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB in bytes
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

# Server configuration
HOST = os.getenv('FLASK_HOST', '0.0.0.0')
PORT = int(os.getenv('FLASK_PORT', 5000))
DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'

# Create uploads folder if it doesn't exist
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
