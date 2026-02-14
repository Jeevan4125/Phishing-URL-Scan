from flask import Flask, render_template, request, jsonify, session, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
import asyncio
import validators
import hashlib
import hmac
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from enhanced_detector import EnhancedPhishingDetector

# Configuration
class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    CACHE_TYPE = 'simple'
    CACHE_DEFAULT_TIMEOUT = 300
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = "200 per day, 50 per hour"

app = Flask(__name__)
app.config.from_object(Config)
app.config['SESSION_TYPE'] = 'filesystem'
app.secret_key = Config.SECRET_KEY

# Initialize extensions correctly
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # Use memory storage for development
)

cache = Cache(app)

# Initialize detector
detector = EnhancedPhishingDetector()

@app.route('/')
def index():
    """Main page"""
    history = session.get('history', [])
    return render_template('index.html', history=history)

@app.route('/check', methods=['POST'])
@limiter.limit("10 per minute")
def check_url():
    """Check URL endpoint"""
    url = request.form.get('url', '').strip()
    
    if not url:
        flash('Please enter a URL', 'error')
        return render_template('index.html')
    
    # Validate URL
    if not validators.url(url):
        if not validators.url('http://' + url):
            flash('Please enter a valid URL (e.g., https://example.com)', 'error')
            return render_template('index.html')
        url = 'http://' + url
    
    try:
        # Run async analysis in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(detector.analyze(url))
        loop.close()
        
        # Store in session for history
        if 'history' not in session:
            session['history'] = []
        
        session['history'].insert(0, {
            'url': url,
            'verdict': result['verdict'],
            'risk_level': result.get('risk_level', 'Unknown'),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
        # Keep only last 20 items
        session['history'] = session['history'][:20]
        session.modified = True
        
        return render_template('index.html', result=result)
    
    except Exception as e:
        flash(f'Error analyzing URL: {str(e)}', 'error')
        return render_template('index.html')

@app.route('/api/check', methods=['GET'])
@limiter.limit("30 per hour")
def api_check():
    """API endpoint for programmatic access"""
    url = request.args.get('url', '').strip()
    api_key = request.headers.get('X-API-Key')
    
    # Simple API key validation (in production, use proper auth)
    if not api_key or not hmac.compare_digest(api_key, Config.SECRET_KEY):
        return jsonify({'error': 'Invalid or missing API key'}), 401
    
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    
    if not validators.url(url):
        if not validators.url('http://' + url):
            return jsonify({'error': 'Invalid URL format'}), 400
        url = 'http://' + url
    
    try:
        # Run async analysis in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(detector.analyze(url))
        loop.close()
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/batch-check', methods=['POST'])
@limiter.limit("10 per hour")
def api_batch_check():
    """Batch URL checking"""
    api_key = request.headers.get('X-API-Key')
    
    if not api_key or not hmac.compare_digest(api_key, Config.SECRET_KEY):
        return jsonify({'error': 'Invalid or missing API key'}), 401
    
    data = request.get_json()
    if not data or 'urls' not in data:
        return jsonify({'error': 'URLs list required'}), 400
    
    urls = data['urls'][:10]  # Limit to 10 URLs
    
    results = []
    for url in urls:
        if validators.url(url):
            try:
                # Run async analysis in sync context
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(detector.analyze(url))
                loop.close()
                
                results.append({
                    'url': url,
                    'result': result
                })
            except Exception as e:
                results.append({
                    'url': url,
                    'error': str(e)
                })
        else:
            results.append({
                'url': url,
                'error': 'Invalid URL format'
            })
    
    return jsonify({
        'total': len(results),
        'results': results
    })

@app.route('/dashboard')
def dashboard():
    """Analytics dashboard"""
    return render_template('dashboard.html')

@app.route('/api/stats')
@cache.cached(timeout=300)  # Cache for 5 minutes
def get_stats():
    """Get global statistics"""
    # In production, this would come from a database
    stats = {
        'total_scans': cache.get('total_scans') or 1247,
        'phishing_detected': cache.get('phishing_detected') or 342,
        'safe_sites': cache.get('safe_sites') or 905,
        'popular_tlds': {
            '.com': 450,
            '.org': 120,
            '.net': 85,
            '.io': 45,
            'other': 547
        },
        'recent_scans': [
            {'url': 'example.com', 'verdict': '🟢 SAFE', 'time': '2 min ago'},
            {'url': 'suspicious-site.xyz', 'verdict': '🔴 PHISHING', 'time': '5 min ago'},
            {'url': 'test-site.org', 'verdict': '🟡 SUSPICIOUS', 'time': '10 min ago'},
            {'url': 'secure-bank.com', 'verdict': '🟢 SAFE', 'time': '15 min ago'},
            {'url': 'login-verify.tk', 'verdict': '🔴 PHISHING', 'time': '20 min ago'}
        ]
    }
    return jsonify(stats)

@app.route('/history')
def history():
    """View scan history"""
    history_list = session.get('history', [])
    return render_template('history.html', history=history_list)

@app.route('/clear-history', methods=['POST'])
def clear_history():
    """Clear scan history"""
    session.pop('history', None)
    flash('History cleared', 'success')
    return jsonify({'success': True})

@app.errorhandler(429)
def ratelimit_handler(e):
    """Rate limit exceeded handler"""
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.'
    }), 429

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.teardown_appcontext
def close_db(error):
    """Clean up resources"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(detector.close())
        loop.close()
    except:
        pass
@app.route('/api/test/google', methods=['POST'])
def test_google_key():
    """Test Google Safe Browsing API key"""
    import requests
    import json
    
    data = request.get_json()
    api_key = data.get('api_key')
    
    if not api_key:
        return jsonify({'success': False, 'error': 'No API key provided'})
    
    # Test the key with a simple request
    test_url = "https://example.com"
    payload = {
        'client': {
            'clientId': 'phishguard-test',
            'clientVersion': '1.0'
        },
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': test_url}]
        }
    }
    
    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'success': True,
                'details': {
                    'status': 'API is working',
                    'matches': data.get('matches', [])
                }
            })
        else:
            error_data = response.json()
            error_message = error_data.get('error', {}).get('message', 'Unknown error')
            return jsonify({
                'success': False,
                'error': f'API Error: {error_message}'
            })
            
    except requests.exceptions.Timeout:
        return jsonify({'success': False, 'error': 'Connection timeout'})
    except requests.exceptions.ConnectionError:
        return jsonify({'success': False, 'error': 'Connection error'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
if __name__ == '__main__':
    app.run(debug=Config.DEBUG, host='0.0.0.0', port=5000)