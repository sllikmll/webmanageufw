import os
from pathlib import Path


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'change-me')
    DATABASE_URL = os.getenv('DATABASE_URL', f"sqlite:///{Path(__file__).resolve().parent.parent / 'data' / 'app.db'}")
    APP_ENCRYPTION_KEY = os.getenv('APP_ENCRYPTION_KEY', 'change-this-key')
