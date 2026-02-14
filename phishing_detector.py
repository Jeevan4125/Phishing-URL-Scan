import re
from urllib.parse import urlparse

class PhishingDetector:
    def __init__(self):
        # Suspicious keywords commonly found in phishing URLs
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'account', 'banking',
            'secure', 'update', 'confirm', 'password', 'credential',
            'paypal', 'ebay', 'apple', 'amazon', 'facebook'
        ]
        
        # Suspicious TLDs often used in phishing
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club'
        ]
    
    def check_https(self, url):
        """Check if URL uses HTTPS protocol"""
        return url.startswith('https://')
    
    def check_ip_address(self, url):
        """Check if URL contains IP address instead of domain name"""
        # Pattern for IPv4 address
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        # Check if domain is an IP address
        if re.search(ip_pattern, domain):
            return True
        return False
    
    def count_dots(self, url):
        """Count number of dots in domain"""
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        return domain.count('.')
    
    def check_suspicious_keywords(self, url):
        """Check for suspicious keywords in URL"""
        url_lower = url.lower()
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                return True
        return False
    
    def check_suspicious_tld(self, url):
        """Check for suspicious top-level domains"""
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                return True
        return False
    
    def check_url_length(self, url):
        """Check if URL is unusually long"""
        return len(url) > 75
    
    def check_special_chars(self, url):
        """Check for excessive special characters"""
        special_chars = ['@', '//', '%', '&', '=', '?']
        count = sum(url.count(char) for char in special_chars)
        return count > 5
    
    def analyze(self, url):
        """
        Analyze URL and return detailed report
        """
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        checks = {
            'HTTPS Enabled': self.check_https(url),
            'Contains IP Address': self.check_ip_address(url),
            'Too Many Dots': self.count_dots(url) > 3,
            'Suspicious Keywords': self.check_suspicious_keywords(url),
            'Suspicious TLD': self.check_suspicious_tld(url),
            'URL Too Long': self.check_url_length(url),
            'Excessive Special Chars': self.check_special_chars(url)
        }
        
        # Calculate risk score
        risk_score = sum(1 for result in checks.values() if result)
        
        # Determine verdict
        if risk_score <= 1:
            verdict = "🟢 SAFE"
            confidence = "Low Risk"
        elif risk_score <= 3:
            verdict = "🟡 SUSPICIOUS"
            confidence = "Medium Risk"
        else:
            verdict = "🔴 SUSPICIOUS"
            confidence = "High Risk"
        
        return {
            'url': url,
            'checks': checks,
            'risk_score': risk_score,
            'verdict': verdict,
            'confidence': confidence
        }
    
    def get_recommendations(self, result):
        """Generate recommendations based on analysis"""
        recommendations = []
        
        if not result['checks']['HTTPS Enabled']:
            recommendations.append("❌ Website doesn't use HTTPS - connection is not secure")
        
        if result['checks']['Contains IP Address']:
            recommendations.append("⚠️ URL uses IP address instead of domain name - common in phishing")
        
        if result['checks']['Too Many Dots']:
            recommendations.append("⚠️ Unusual number of dots in domain name")
        
        if result['checks']['Suspicious Keywords']:
            recommendations.append("⚠️ Contains words commonly used in phishing URLs")
        
        if result['checks']['Suspicious TLD']:
            recommendations.append("⚠️ Uses suspicious top-level domain")
        
        if result['checks']['URL Too Long']:
            recommendations.append("⚠️ Unusually long URL - may hide malicious intent")
        
        return recommendations if recommendations else ["✅ No major red flags detected"]