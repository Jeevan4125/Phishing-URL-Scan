import re
import asyncio
import tldextract
import math
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Any, List, Tuple
from utils.api_handlers import APIClient

class EnhancedPhishingDetector:
    """Enhanced phishing detection with ML and API integration"""
    
    def __init__(self):
        self.api_client = APIClient()
        
        # Suspicious patterns
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'account', 'banking',
            'secure', 'update', 'confirm', 'password', 'credential',
            'paypal', 'ebay', 'apple', 'amazon', 'facebook', 'google',
            'microsoft', 'netflix', 'instagram', 'whatsapp', 'paypal'
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club',
            '.work', '.download', '.review', '.loan', '.win', '.bid'
        ]
        
        # URL shorteners (often used to hide malicious URLs)
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'tiny.cc',
            'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc'
        ]
        
        # ML weights (would be trained in production)
        self.weights = {
            'https': 0.15,
            'ip_address': 0.20,
            'dots_count': 0.10,
            'keywords': 0.15,
            'tld': 0.10,
            'length': 0.05,
            'shortener': 0.10,
            'special_chars': 0.05,
            'subdomains': 0.10
        }
    
    async def analyze(self, url: str) -> Dict[str, Any]:
        """
        Comprehensive URL analysis using multiple techniques
        """
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Parse URL
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Run all checks concurrently
        checks_task = asyncio.create_task(self._run_checks(url, parsed, extracted))
        api_task = asyncio.create_task(self.api_client.check_all(url))
        
        # Wait for both
        checks_result = await checks_task
        api_results = await api_task
        
        # Calculate scores
        heuristic_score = self._calculate_heuristic_score(checks_result)
        api_score = self._calculate_api_score(api_results)
        
        # Combined score (weighted)
        combined_score = (heuristic_score * 0.6) + (api_score * 0.4)
        
        # Determine verdict
        verdict, confidence = self._get_verdict(combined_score, checks_result, api_results)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(checks_result, api_results)
        
        return {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'heuristic_checks': checks_result,
            'api_results': api_results,
            'scores': {
                'heuristic': round(heuristic_score, 2),
                'api': round(api_score, 2),
                'combined': round(combined_score, 2)
            },
            'verdict': verdict,
            'confidence': confidence,
            'recommendations': recommendations,
            'risk_level': self._get_risk_level(combined_score)
        }
    
    async def _run_checks(self, url: str, parsed, extracted) -> Dict[str, Any]:
        """Run all heuristic checks"""
        
        domain = parsed.netloc or parsed.path
        subdomain = extracted.subdomain
        domain_name = extracted.domain
        suffix = extracted.suffix
        
        checks = {
            'https': self._check_https(url),
            'ip_address': self._check_ip_address(domain),
            'dots_count': domain.count('.'),
            'dots_excessive': domain.count('.') > 3,
            'suspicious_keywords': self._check_suspicious_keywords(url),
            'suspicious_tld': self._check_suspicious_tld(domain),
            'url_length': len(url),
            'url_too_long': len(url) > 100,
            'url_shortener': self._check_url_shortener(domain),
            'special_chars_count': self._count_special_chars(url),
            'special_chars_excessive': self._count_special_chars(url) > 5,
            'subdomain_count': len(subdomain.split('.')) if subdomain else 0,
            'subdomains_excessive': len(subdomain.split('.')) > 2 if subdomain else False,
            'contains_at_symbol': '@' in url,
            'double_slash_redirect': url.count('//') > 1,
            'hyphen_count': domain.count('-'),
            'hyphen_suspicious': domain.count('-') > 2,
            'digit_count': sum(c.isdigit() for c in domain),
            'digit_ratio': sum(c.isdigit() for c in domain) / len(domain) if domain else 0,
            'entropy': self._calculate_entropy(domain)
        }
        
        return checks
    
    def _check_https(self, url: str) -> bool:
        """Check if URL uses HTTPS"""
        return url.startswith('https://')
    
    def _check_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, domain))
    
    def _check_suspicious_keywords(self, url: str) -> List[str]:
        """Find suspicious keywords in URL"""
        url_lower = url.lower()
        found = []
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                found.append(keyword)
        return found
    
    def _check_suspicious_tld(self, domain: str) -> bool:
        """Check for suspicious TLDs"""
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                return True
        return False
    
    def _check_url_shortener(self, domain: str) -> bool:
        """Check if URL uses a shortener service"""
        return any(shortener in domain for shortener in self.url_shorteners)
    
    def _count_special_chars(self, url: str) -> int:
        """Count special characters in URL"""
        special_chars = ['@', '//', '%', '&', '=', '?', '-', '_', '~']
        return sum(url.count(char) for char in special_chars)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of string"""
        if not text:
            return 0
        
        entropy = 0
        for i in range(256):
            char = chr(i)
            freq = text.count(char)
            if freq > 0:
                freq = float(freq) / len(text)
                entropy -= freq * math.log(freq, 2)
        return entropy
    
    def _calculate_heuristic_score(self, checks: Dict) -> float:
        """Calculate risk score from heuristic checks"""
        score = 0.0
        
        # HTTPS (weighted negatively - good)
        if not checks['https']:
            score += self.weights['https']
        
        # IP address
        if checks['ip_address']:
            score += self.weights['ip_address']
        
        # Dots excessive
        if checks['dots_excessive']:
            score += self.weights['dots_count']
        
        # Keywords
        if checks['suspicious_keywords']:
            score += self.weights['keywords'] * min(len(checks['suspicious_keywords']) / 3, 1)
        
        # Suspicious TLD
        if checks['suspicious_tld']:
            score += self.weights['tld']
        
        # URL too long
        if checks['url_too_long']:
            score += self.weights['length']
        
        # URL shortener
        if checks['url_shortener']:
            score += self.weights['shortener']
        
        # Special chars excessive
        if checks['special_chars_excessive']:
            score += self.weights['special_chars']
        
        # Subdomains excessive
        if checks['subdomains_excessive']:
            score += self.weights['subdomains']
        
        # Normalize to 0-1 range
        return min(score, 1.0)
    
    def _calculate_api_score(self, api_results: Dict) -> float:
        """Calculate risk score from API results"""
        score = 0.0
        valid_results = 0
        
        # Google Safe Browsing
        gsb = api_results.get('google_sb', {})
        if isinstance(gsb, dict) and 'safe' in gsb:
            if not gsb['safe']:
                score += 0.4  # High confidence if Google flags it
            valid_results += 1
        
        # VirusTotal
        vt = api_results.get('virustotal', {})
        if isinstance(vt, dict) and 'stats' in vt:
            malicious = vt['stats'].get('malicious', 0)
            suspicious = vt['stats'].get('suspicious', 0)
            total = sum(vt['stats'].values()) if sum(vt['stats'].values()) > 0 else 1
            
            vt_score = (malicious + suspicious * 0.5) / total
            score += vt_score * 0.3
            valid_results += 1
        
        # IPQualityScore
        ipqs = api_results.get('ipqs', {})
        if isinstance(ipqs, dict) and 'risk_score' in ipqs:
            ipqs_score = ipqs['risk_score'] / 100  # Normalize
            score += ipqs_score * 0.3
            
            # Additional flags
            if ipqs.get('phishing', False):
                score += 0.2
            if ipqs.get('malware', False):
                score += 0.2
            
            valid_results += 1
        
        # Average score if we have results
        if valid_results > 0:
            return min(score / valid_results, 1.0)
        return 0.5  # Neutral if no API results
    
    def _get_verdict(self, score: float, checks: Dict, api_results: Dict) -> Tuple[str, str]:
        """Determine verdict based on scores"""
        
        # Check for high-confidence API flags
        for api_name, result in api_results.items():
            if isinstance(result, dict):
                # Google Safe Browsing match
                if api_name == 'google_sb' and 'matches' in result and result['matches']:
                    return "🔴 PHISHING", "High (Google Safe Browsing)"
                
                # VirusTotal malicious
                if api_name == 'virustotal' and 'stats' in result:
                    if result['stats'].get('malicious', 0) > 5:
                        return "🔴 PHISHING", "High (Multiple detections)"
                
                # IPQS phishing flag
                if api_name == 'ipqs' and result.get('phishing', False):
                    return "🔴 PHISHING", "High (IPQualityScore)"
        
        # Heuristic-based verdict
        if score < 0.2:
            return "🟢 SAFE", "High"
        elif score < 0.4:
            return "🟡 SUSPICIOUS", "Medium"
        elif score < 0.6:
            return "🟠 SUSPICIOUS", "High"
        else:
            return "🔴 PHISHING", "Very High"
    
    def _get_risk_level(self, score: float) -> str:
        """Get risk level description"""
        if score < 0.2:
            return "Low Risk"
        elif score < 0.4:
            return "Medium Risk"
        elif score < 0.6:
            return "High Risk"
        else:
            return "Critical Risk"
    
    def _generate_recommendations(self, checks: Dict, api_results: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # HTTPS recommendations
        if not checks['https']:
            recommendations.append("🔒 Enable HTTPS - Your connection is not encrypted")
        
        # IP address warning
        if checks['ip_address']:
            recommendations.append("⚠️ URL uses IP address - Legitimate sites use domain names")
        
        # Suspicious keywords
        if checks['suspicious_keywords']:
            keywords = ', '.join(checks['suspicious_keywords'][:3])
            recommendations.append(f"⚠️ Contains suspicious words: {keywords}")
        
        # URL shortener
        if checks['url_shortener']:
            recommendations.append("🔗 URL shortener detected - Be careful where it redirects")
        
        # Excessive subdomains
        if checks['subdomains_excessive']:
            recommendations.append("🌐 Too many subdomains - This can hide the real website")
        
        # API-specific recommendations
        for api_name, result in api_results.items():
            if isinstance(result, dict):
                if api_name == 'virustotal' and 'stats' in result:
                    malicious = result['stats'].get('malicious', 0)
                    if malicious > 0:
                        recommendations.append(f"🦠 VirusTotal: {malicious} security vendors flagged this URL")
                
                if api_name == 'ipqs' and result.get('risk_score', 0) > 75:
                    recommendations.append(f"📊 IPQualityScore: Very high risk score ({result['risk_score']}/100)")
        
        if not recommendations:
            recommendations.append("✅ No immediate threats detected. Still, always verify website authenticity.")
        
        return recommendations
    
    async def close(self):
        """Clean up resources"""
        await self.api_client.close()