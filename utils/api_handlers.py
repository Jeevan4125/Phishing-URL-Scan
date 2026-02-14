import aiohttp
import asyncio
import base64
import json
from typing import Dict, Any, Optional
from urllib.parse import quote
from config import config
from utils.cache_manager import cached, CacheManager

class APIClient:
    """Handle external API calls"""
    
    def __init__(self):
        self.session = None
        self.cache = CacheManager()
        self.api_keys = {
            'google': config.GOOGLE_SAFE_BROWSING_KEY,
            'virustotal': config.VIRUSTOTAL_KEY,
            'ipqs': config.IPQUALITYSCORE_KEY
        }
    
    async def _get_session(self):
        """Get or create aiohttp session"""
        if self.session is None:
            self.session = aiohttp.ClientSession()
        return self.session
    
    async def close(self):
        """Close session"""
        if self.session:
            await self.session.close()
    
    @cached('google_sb', timeout=3600)
    async def check_google_safe_browsing(self, url: str) -> Dict[str, Any]:
        """Check URL against Google Safe Browsing"""
        if not self.api_keys['google']:
            return {'error': 'Google API key not configured'}
        
        session = await self._get_session()
        
        payload = {
            'client': {
                'clientId': 'phishing-detector',
                'clientVersion': '1.0.0'
            },
            'threatInfo': {
                'threatTypes': [
                    'MALWARE', 'SOCIAL_ENGINEERING', 
                    'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'
                ],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}]
            }
        }
        
        try:
            async with session.post(
                f"{config.GOOGLE_SAFE_BROWSING_URL}?key={self.api_keys['google']}",
                json=payload
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'safe': 'matches' not in data,
                        'matches': data.get('matches', []),
                        'source': 'Google Safe Browsing'
                    }
                else:
                    return {'error': f'Google API error: {response.status}'}
        except Exception as e:
            return {'error': str(e)}
    
    @cached('virustotal', timeout=3600)
    async def check_virustotal(self, url: str) -> Dict[str, Any]:
        """Check URL against VirusTotal"""
        if not self.api_keys['virustotal']:
            return {'error': 'VirusTotal API key not configured'}
        
        session = await self._get_session()
        
        # Encode URL for VirusTotal
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {
            'x-apikey': self.api_keys['virustotal']
        }
        
        try:
            # Get URL report
            async with session.get(
                f"{config.VIRUSTOTAL_URL}/{url_id}",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    
                    return {
                        'safe': stats.get('malicious', 0) == 0,
                        'stats': stats,
                        'total_votes': data.get('data', {}).get('attributes', {}).get('total_votes', {}),
                        'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0),
                        'source': 'VirusTotal'
                    }
                elif response.status == 404:
                    # URL not found in VT, submit it
                    return await self._submit_to_virustotal(url)
                else:
                    return {'error': f'VirusTotal error: {response.status}'}
        except Exception as e:
            return {'error': str(e)}
    
    async def _submit_to_virustotal(self, url: str) -> Dict[str, Any]:
        """Submit URL to VirusTotal for analysis"""
        session = await self._get_session()
        
        headers = {
            'x-apikey': self.api_keys['virustotal'],
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = {'url': url}
        
        try:
            async with session.post(
                config.VIRUSTOTAL_URL,
                headers=headers,
                data=data
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'submitted': True,
                        'scan_id': data.get('data', {}).get('id'),
                        'message': 'URL submitted for scanning',
                        'source': 'VirusTotal'
                    }
                else:
                    return {'error': f'VirusTotal submission error: {response.status}'}
        except Exception as e:
            return {'error': str(e)}
    
    @cached('ipqs', timeout=3600)
    async def check_ipqualityscore(self, url: str) -> Dict[str, Any]:
        """Check URL with IPQualityScore"""
        if not self.api_keys['ipqs']:
            return {'error': 'IPQualityScore API key not configured'}
        
        session = await self._get_session()
        
        encoded_url = quote(url, safe='')
        api_url = config.IPQUALITYSCORE_URL.format(
            api_key=self.api_keys['ipqs'],
            url=encoded_url
        )
        
        params = {
            'strictness': 1,
            'fast': True
        }
        
        try:
            async with session.get(api_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    return {
                        'safe': data.get('unsafe', True) == False,
                        'risk_score': data.get('risk_score', 0),
                        'domain_rank': data.get('domain_rank', 0),
                        'parking': data.get('parking', False),
                        'spamming': data.get('spamming', False),
                        'malware': data.get('malware', False),
                        'phishing': data.get('phishing', False),
                        'adult': data.get('adult', False),
                        'category': data.get('category', 'Unknown'),
                        'source': 'IPQualityScore'
                    }
                else:
                    return {'error': f'IPQS error: {response.status}'}
        except Exception as e:
            return {'error': str(e)}
    
    async def check_all(self, url: str) -> Dict[str, Any]:
        """Check URL against all APIs concurrently"""
        tasks = [
            self.check_google_safe_browsing(url),
            self.check_virustotal(url),
            self.check_ipqualityscore(url)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            'google_sb': results[0] if not isinstance(results[0], Exception) else {'error': str(results[0])},
            'virustotal': results[1] if not isinstance(results[1], Exception) else {'error': str(results[1])},
            'ipqs': results[2] if not isinstance(results[2], Exception) else {'error': str(results[2])}
        }