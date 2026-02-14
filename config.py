import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Application configuration"""
    
    # API Keys
    GOOGLE_SAFE_BROWSING_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    VIRUSTOTAL_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    IPQUALITYSCORE_KEY = os.getenv('IPQUALITYSCORE_API_KEY')
    
    # App Settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    
    # Cache Settings
    CACHE_TIMEOUT = int(os.getenv('CACHE_TIMEOUT', 3600))
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
    
    # Rate Limiting
    RATE_LIMIT = 100  # requests per hour per IP
    
    # API Endpoints
    GOOGLE_SAFE_BROWSING_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
    VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/urls'
    IPQUALITYSCORE_URL = 'https://ipqualityscore.com/api/json/url/{api_key}/{url}'

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    
# Export config
config = Config()