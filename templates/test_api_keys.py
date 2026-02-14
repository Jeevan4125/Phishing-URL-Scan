#!/usr/bin/env python3
"""
Enhanced API Key Tester for Phishing URL Detector
Advanced testing with detailed diagnostics, quota checking, and multiple test modes
"""

import os
import sys
import json
import time
import base64
import requests
import platform
from datetime import datetime
from urllib.parse import quote
from dotenv import load_dotenv, set_key
from typing import Dict, Any, Optional, Tuple
import argparse
from colorama import init, Fore, Style, Back

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Load environment variables
load_dotenv()

class Colors:
    """Color constants for beautiful output"""
    HEADER = Fore.MAGENTA + Style.BRIGHT
    INFO = Fore.CYAN
    SUCCESS = Fore.GREEN + Style.BRIGHT
    WARNING = Fore.YELLOW
    ERROR = Fore.RED + Style.BRIGHT
    DEBUG = Fore.BLUE
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

class EnhancedAPITester:
    def __init__(self, verbose: bool = False, timeout: int = 15):
        self.results = {
            'google': {
                'status': '⏳ Pending',
                'details': None,
                'latency': None,
                'quota': None,
                'errors': []
            },
            'virustotal': {
                'status': '⏳ Pending',
                'details': None,
                'latency': None,
                'quota': None,
                'errors': []
            },
            'ipqs': {
                'status': '⏳ Pending',
                'details': None,
                'latency': None,
                'quota': None,
                'errors': []
            }
        }
        
        self.test_urls = {
            'safe': 'https://example.com',
            'test': 'https://google.com',
            'malicious': 'http://testsafebrowsing.appspot.com/s/malware.html'  # Google's test URL
        }
        
        self.verbose = verbose
        self.timeout = timeout
        self.start_time = None
        
    def print_banner(self):
        """Print beautiful banner"""
        banner = f"""
{Colors.HEADER}╔══════════════════════════════════════════════════════════╗
║         🔐 ENHANCED API KEY VALIDATION TOOL v2.0          ║
║         Phishing URL Detector - Multi-API Tester           ║
╚══════════════════════════════════════════════════════════╝{Colors.RESET}
        """
        print(banner)
        
    def print_section(self, title: str):
        """Print section header"""
        print(f"\n{Colors.HEADER}┌─ {title} {'─' * (60 - len(title))}┐{Colors.RESET}")
        
    def print_subsection(self, title: str):
        """Print subsection"""
        print(f"\n{Colors.INFO}▶ {title}{Colors.RESET}")
        
    def print_result(self, api_name: str, status: str, details: str = None, 
                    latency: float = None, quota: str = None):
        """Print formatted result"""
        if "WORKING" in status or "✅" in status:
            status_icon = "✅"
            status_color = Colors.SUCCESS
        elif "FAILED" in status or "❌" in status:
            status_icon = "❌"
            status_color = Colors.ERROR
        elif "CONFIGURED" in status or "⚠️" in status:
            status_icon = "⚠️"
            status_color = Colors.WARNING
        else:
            status_icon = "⏳"
            status_color = Colors.INFO
            
        print(f"\n{status_color}{status_icon} {api_name}: {status}{Colors.RESET}")
        if details:
            print(f"   {Colors.INFO}📋{Colors.RESET} {details}")
        if latency:
            latency_color = Colors.SUCCESS if latency < 500 else Colors.WARNING if latency < 1000 else Colors.ERROR
            print(f"   {Colors.INFO}⚡{Colors.RESET} Latency: {latency_color}{latency:.0f}ms{Colors.RESET}")
        if quota:
            print(f"   {Colors.INFO}📊{Colors.RESET} Quota: {quota}")
            
    def measure_latency(self, func, *args, **kwargs):
        """Measure function latency"""
        start = time.time()
        result = func(*args, **kwargs)
        latency = (time.time() - start) * 1000  # Convert to milliseconds
        return result, latency

    def check_network_connectivity(self) -> bool:
        """Check internet connectivity"""
        self.print_subsection("Network Connectivity Check")
        try:
            response = requests.get("https://www.google.com", timeout=5)
            if response.status_code == 200:
                print(f"{Colors.SUCCESS}✅ Internet connection: OK{Colors.RESET}")
                return True
        except:
            print(f"{Colors.ERROR}❌ No internet connection detected{Colors.RESET}")
            return False
        return False

    def test_google_safe_browsing(self) -> Tuple[bool, Dict]:
        """Enhanced Google Safe Browsing API test"""
        self.print_subsection("Google Safe Browsing API Test")
        
        api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
        
        # Check if configured
        if not api_key or api_key == 'your_google_api_key_here':
            self.results['google'] = {
                'status': '⚠️ NOT CONFIGURED',
                'details': 'API key not found in .env file',
                'latency': None,
                'quota': None,
                'errors': ['Missing API key']
            }
            self.print_result('Google Safe Browsing', 'NOT CONFIGURED', 
                            'Add your API key to .env file')
            return False, self.results['google']
        
        # Validate key format
        if len(api_key) < 20:
            self.results['google'] = {
                'status': '❌ INVALID FORMAT',
                'details': 'API key appears to be too short',
                'latency': None,
                'quota': None,
                'errors': ['Invalid key format']
            }
            self.print_result('Google Safe Browsing', 'INVALID FORMAT', 
                            f'Key length: {len(api_key)} (expected > 20 chars)')
            return False, self.results['google']
        
        print(f"{Colors.INFO}🔑 API Key: {Colors.BOLD}{api_key[:8]}...{api_key[-6:]}{Colors.RESET}")
        
        # Test endpoint
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        
        # Test with safe URL
        payload = {
            'client': {
                'clientId': 'phishing-detector-test',
                'clientVersion': '2.0.0'
            },
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': self.test_urls['safe']}]
            }
        }
        
        try:
            print(f"{Colors.INFO}📡 Testing with safe URL...{Colors.RESET}")
            
            # Measure latency
            def make_request():
                return requests.post(url, json=payload, timeout=self.timeout)
            
            response, latency = self.measure_latency(make_request)
            
            if self.verbose:
                print(f"{Colors.DEBUG}🔧 Request Details:{Colors.RESET}")
                print(f"   URL: {url}")
                print(f"   Method: POST")
                print(f"   Payload size: {len(json.dumps(payload))} bytes")
            
            if response.status_code == 200:
                data = response.json()
                
                # Try to check quota (if available through another endpoint)
                quota_info = self.check_google_quota(api_key)
                
                self.results['google'] = {
                    'status': '✅ WORKING',
                    'details': 'API responded successfully',
                    'latency': latency,
                    'quota': quota_info,
                    'errors': []
                }
                
                # Test with known malicious URL if verbose
                if self.verbose:
                    self.test_google_malicious(api_key)
                
                self.print_result('Google Safe Browsing', '✅ WORKING', 
                                'API key is valid and responding', 
                                latency, quota_info)
                return True, self.results['google']
                
            elif response.status_code == 400:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('message', 'Bad request')
                self.results['google'] = {
                    'status': '❌ FAILED',
                    'details': f'Bad request: {error_msg}',
                    'latency': latency,
                    'quota': None,
                    'errors': [error_msg]
                }
                self.print_result('Google Safe Browsing', '❌ FAILED', 
                                f'Bad request format: {error_msg}', latency)
                
            elif response.status_code == 403:
                self.results['google'] = {
                    'status': '❌ FORBIDDEN',
                    'details': 'API key lacks permissions or billing not enabled',
                    'latency': latency,
                    'quota': None,
                    'errors': ['Access forbidden - enable billing?']
                }
                self.print_result('Google Safe Browsing', '❌ FORBIDDEN', 
                                'API key lacks permissions or billing not enabled', latency)
                
            else:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('message', 'Unknown error')
                self.results['google'] = {
                    'status': '❌ FAILED',
                    'details': f'HTTP {response.status_code}: {error_msg}',
                    'latency': latency,
                    'quota': None,
                    'errors': [error_msg]
                }
                self.print_result('Google Safe Browsing', '❌ FAILED', 
                                f'HTTP {response.status_code}: {error_msg}', latency)
            
        except requests.exceptions.Timeout:
            self.results['google'] = {
                'status': '❌ TIMEOUT',
                'details': f'Connection timeout after {self.timeout}s',
                'latency': None,
                'quota': None,
                'errors': ['Request timeout']
            }
            self.print_result('Google Safe Browsing', '❌ TIMEOUT', 
                            f'Connection timeout after {self.timeout}s')
            
        except requests.exceptions.ConnectionError:
            self.results['google'] = {
                'status': '❌ CONNECTION ERROR',
                'details': 'Could not connect to Google API',
                'latency': None,
                'quota': None,
                'errors': ['Network connection failed']
            }
            self.print_result('Google Safe Browsing', '❌ CONNECTION ERROR', 
                            'Could not connect to Google API - check internet')
            
        except Exception as e:
            self.results['google'] = {
                'status': '❌ ERROR',
                'details': str(e),
                'latency': None,
                'quota': None,
                'errors': [str(e)]
            }
            self.print_result('Google Safe Browsing', '❌ ERROR', str(e))
        
        return False, self.results['google']

    def test_google_malicious(self, api_key: str):
        """Test with known malicious URL (for verbose mode)"""
        print(f"\n{Colors.DEBUG}🔬 Testing with known malicious URL...{Colors.RESET}")
        
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        
        payload = {
            'client': {'clientId': 'test', 'clientVersion': '1.0'},
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': self.test_urls['malicious']}]
            }
        }
        
        try:
            response, latency = self.measure_latency(
                lambda: requests.post(url, json=payload, timeout=self.timeout)
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'matches' in data:
                    print(f"{Colors.SUCCESS}   ✅ API correctly detected threats ({latency:.0f}ms){Colors.RESET}")
                    for match in data['matches']:
                        print(f"      • {match['threatType']} detected")
                else:
                    print(f"{Colors.WARNING}   ⚠️ No threats detected for test URL (unexpected){Colors.RESET}")
            else:
                print(f"{Colors.WARNING}   ⚠️ Test with malicious URL returned {response.status_code}{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.ERROR}   ❌ Malicious URL test failed: {e}{Colors.RESET}")

    def check_google_quota(self, api_key: str) -> Optional[str]:
        """Check Google API quota (if available)"""
        try:
            # Note: This uses a different endpoint that might require additional setup
            # This is a simulated quota check for demonstration
            return "10,000/10,000 requests/day (simulated)"
        except:
            return None

    def test_virustotal(self) -> Tuple[bool, Dict]:
        """Enhanced VirusTotal API test"""
        self.print_subsection("VirusTotal API Test")
        
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        
        if not api_key or api_key == 'your_virustotal_api_key_here':
            self.results['virustotal'] = {
                'status': '⚠️ NOT CONFIGURED',
                'details': 'API key not found in .env file',
                'latency': None,
                'quota': None,
                'errors': ['Missing API key']
            }
            self.print_result('VirusTotal', 'NOT CONFIGURED', 
                            'Add your API key to .env file')
            return False, self.results['virustotal']
        
        print(f"{Colors.INFO}🔑 API Key: {Colors.BOLD}{api_key[:8]}...{api_key[-6:]}{Colors.RESET}")
        
        # Encode URL
        test_url = self.test_urls['safe']
        url_id = base64.urlsafe_b64encode(test_url.encode()).decode().strip("=")
        
        headers = {'x-apikey': api_key}
        
        try:
            print(f"{Colors.INFO}📡 Checking URL in VirusTotal database...{Colors.RESET}")
            
            def make_request():
                return requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers,
                    timeout=self.timeout
                )
            
            response, latency = self.measure_latency(make_request)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                # Check rate limit headers
                quota_info = None
                if 'X-RateLimit-Remaining' in response.headers:
                    quota_info = f"{response.headers.get('X-RateLimit-Remaining', '?')} requests remaining"
                
                self.results['virustotal'] = {
                    'status': '✅ WORKING',
                    'details': f"Stats - Malicious: {stats.get('malicious', 0)}, "
                              f"Suspicious: {stats.get('suspicious', 0)}",
                    'latency': latency,
                    'quota': quota_info,
                    'errors': []
                }
                self.print_result('VirusTotal', '✅ WORKING', 
                                f"Found in database - Malicious: {stats.get('malicious', 0)}", 
                                latency, quota_info)
                return True, self.results['virustotal']
                
            elif response.status_code == 404:
                print(f"{Colors.INFO}📤 URL not found, attempting to submit...{Colors.RESET}")
                return self.test_virustotal_submit(api_key, test_url)
                
            elif response.status_code == 401:
                self.results['virustotal'] = {
                    'status': '❌ INVALID KEY',
                    'details': 'Invalid API key',
                    'latency': latency,
                    'quota': None,
                    'errors': ['Invalid API key']
                }
                self.print_result('VirusTotal', '❌ INVALID KEY', 
                                'Invalid API key - Check your key', latency)
            else:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('message', 'Unknown error')
                self.results['virustotal'] = {
                    'status': '❌ FAILED',
                    'details': f'HTTP {response.status_code}: {error_msg}',
                    'latency': latency,
                    'quota': None,
                    'errors': [error_msg]
                }
                self.print_result('VirusTotal', '❌ FAILED', 
                                f'HTTP {response.status_code}: {error_msg}', latency)
                
        except Exception as e:
            self.results['virustotal'] = {
                'status': '❌ ERROR',
                'details': str(e),
                'latency': None,
                'quota': None,
                'errors': [str(e)]
            }
            self.print_result('VirusTotal', '❌ ERROR', str(e))
        
        return False, self.results['virustotal']

    def test_virustotal_submit(self, api_key: str, url: str) -> Tuple[bool, Dict]:
        """Submit URL to VirusTotal"""
        headers = {
            'x-apikey': api_key,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = {'url': url}
        
        try:
            def make_request():
                return requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data=data,
                    timeout=self.timeout
                )
            
            response, latency = self.measure_latency(make_request)
            
            if response.status_code == 200:
                data = response.json()
                scan_id = data.get('data', {}).get('id')
                self.results['virustotal'] = {
                    'status': '✅ WORKING',
                    'details': f'URL submitted for scanning',
                    'latency': latency,
                    'quota': 'Submission successful',
                    'errors': []
                }
                self.print_result('VirusTotal', '✅ WORKING', 
                                f'URL submitted - Scan ID: {scan_id[:20]}...', latency)
                return True, self.results['virustotal']
            else:
                self.results['virustotal'] = {
                    'status': '❌ FAILED',
                    'details': f'Submission failed: HTTP {response.status_code}',
                    'latency': latency,
                    'quota': None,
                    'errors': [f'HTTP {response.status_code}']
                }
                self.print_result('VirusTotal', '❌ FAILED', 
                                f'Submission failed: HTTP {response.status_code}', latency)
                
        except Exception as e:
            self.results['virustotal'] = {
                'status': '❌ ERROR',
                'details': str(e),
                'latency': None,
                'quota': None,
                'errors': [str(e)]
            }
            self.print_result('VirusTotal', '❌ ERROR', str(e))
        
        return False, self.results['virustotal']

    def test_ipqualityscore(self) -> Tuple[bool, Dict]:
        """Enhanced IPQualityScore API test"""
        self.print_subsection("IPQualityScore API Test")
        
        api_key = os.getenv('IPQUALITYSCORE_API_KEY')
        
        if not api_key or api_key == 'your_ipqs_api_key_here':
            self.results['ipqs'] = {
                'status': '⚠️ NOT CONFIGURED',
                'details': 'API key not found in .env file',
                'latency': None,
                'quota': None,
                'errors': ['Missing API key']
            }
            self.print_result('IPQualityScore', 'NOT CONFIGURED', 
                            'Add your API key to .env file')
            return False, self.results['ipqs']
        
        print(f"{Colors.INFO}🔑 API Key: {Colors.BOLD}{api_key[:8]}...{api_key[-6:]}{Colors.RESET}")
        
        test_url = self.test_urls['safe']
        encoded_url = quote(test_url, safe='')
        
        try:
            print(f"{Colors.INFO}📡 Checking URL with IPQualityScore...{Colors.RESET}")
            
            def make_request():
                return requests.get(
                    f"https://ipqualityscore.com/api/json/url/{api_key}/{encoded_url}",
                    params={'strictness': 1, 'fast': True},
                    timeout=self.timeout
                )
            
            response, latency = self.measure_latency(make_request)
            
            if response.status_code == 200:
                data = response.json()
                
                if 'success' in data and data['success'] is False:
                    error_message = data.get('message', 'Unknown error')
                    self.results['ipqs'] = {
                        'status': '❌ API ERROR',
                        'details': f'API Error: {error_message}',
                        'latency': latency,
                        'quota': None,
                        'errors': [error_message]
                    }
                    self.print_result('IPQualityScore', '❌ API ERROR', 
                                    f'API Error: {error_message}', latency)
                else:
                    risk_score = data.get('risk_score', 0)
                    unsafe = data.get('unsafe', False)
                    
                    # Parse quota info if available
                    quota_info = None
                    if 'X-Quota-Limit' in response.headers:
                        quota_info = f"Quota: {response.headers.get('X-Quota-Remaining', '?')}/{response.headers.get('X-Quota-Limit', '?')}"
                    
                    self.results['ipqs'] = {
                        'status': '✅ WORKING',
                        'details': f'Risk Score: {risk_score}, Unsafe: {unsafe}',
                        'latency': latency,
                        'quota': quota_info,
                        'errors': []
                    }
                    
                    # Additional flags in verbose mode
                    if self.verbose:
                        flags = []
                        for flag in ['phishing', 'malware', 'spamming', 'parking']:
                            if data.get(flag):
                                flags.append(flag)
                        if flags:
                            print(f"{Colors.WARNING}   ⚠️ Detected flags: {', '.join(flags)}{Colors.RESET}")
                    
                    self.print_result('IPQualityScore', '✅ WORKING', 
                                    f'Risk Score: {risk_score}', latency, quota_info)
                    return True, self.results['ipqs']
                    
            elif response.status_code == 401:
                self.results['ipqs'] = {
                    'status': '❌ INVALID KEY',
                    'details': 'Invalid API key',
                    'latency': latency,
                    'quota': None,
                    'errors': ['Invalid API key']
                }
                self.print_result('IPQualityScore', '❌ INVALID KEY', 
                                'Invalid API key - Check your key', latency)
            elif response.status_code == 429:
                self.results['ipqs'] = {
                    'status': '❌ RATE LIMITED',
                    'details': 'Rate limit exceeded',
                    'latency': latency,
                    'quota': None,
                    'errors': ['Rate limit exceeded']
                }
                self.print_result('IPQualityScore', '❌ RATE LIMITED', 
                                'Rate limit exceeded - Try again later', latency)
            else:
                self.results['ipqs'] = {
                    'status': '❌ FAILED',
                    'details': f'HTTP {response.status_code}',
                    'latency': latency,
                    'quota': None,
                    'errors': [f'HTTP {response.status_code}']
                }
                self.print_result('IPQualityScore', '❌ FAILED', 
                                f'HTTP {response.status_code}', latency)
                
        except Exception as e:
            self.results['ipqs'] = {
                'status': '❌ ERROR',
                'details': str(e),
                'latency': None,
                'quota': None,
                'errors': [str(e)]
            }
            self.print_result('IPQualityScore', '❌ ERROR', str(e))
        
        return False, self.results['ipqs']

    def save_results_to_file(self, filename: str = "api_test_results.json"):
        """Save test results to JSON file"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'system': {
                'platform': platform.platform(),
                'python_version': sys.version,
                'hostname': platform.node()
            },
            'results': self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n{Colors.SUCCESS}📁 Results saved to {filename}{Colors.RESET}")

    def update_env_file(self, api_name: str, api_key: str):
        """Update .env file with new API key"""
        env_file = '.env'
        key_map = {
            'google': 'GOOGLE_SAFE_BROWSING_API_KEY',
            'virustotal': 'VIRUSTOTAL_API_KEY',
            'ipqs': 'IPQUALITYSCORE_API_KEY'
        }
        
        if api_name in key_map:
            set_key(env_file, key_map[api_name], api_key)
            print(f"{Colors.SUCCESS}✅ Updated {key_map[api_name]} in .env file{Colors.RESET}")

    def run_single_test(self, api_name: str):
        """Run a single API test"""
        if api_name == 'google':
            return self.test_google_safe_browsing()
        elif api_name == 'virustotal':
            return self.test_virustotal()
        elif api_name == 'ipqs':
            return self.test_ipqualityscore()
        else:
            print(f"{Colors.ERROR}❌ Unknown API: {api_name}{Colors.RESET}")
            return False, None

    def run_all_tests(self) -> Tuple[int, int, int]:
        """Run all API tests with enhanced reporting"""
        self.print_banner()
        
        # Check network first
        if not self.check_network_connectivity():
            print(f"\n{Colors.ERROR}❌ Cannot proceed without internet connection{Colors.RESET}")
            return 0, 3, 0
        
        self.print_section("🔬 RUNNING API TESTS")
        
        # Run tests
        self.test_google_safe_browsing()
        self.test_virustotal()
        self.test_ipqualityscore()
        
        # Print summary
        self.print_section("📊 TEST SUMMARY REPORT")
        
        working = 0
        failed = 0
        not_configured = 0
        
        for api, result in self.results.items():
            status = result['status']
            if 'WORKING' in status or '✅' in status:
                working += 1
                status_color = Colors.SUCCESS
            elif 'CONFIGURED' in status or '⚠️' in status:
                not_configured += 1
                status_color = Colors.WARNING
            else:
                failed += 1
                status_color = Colors.ERROR
            
            print(f"\n{status_color}{api.upper()}:{Colors.RESET}")
            print(f"   Status: {status_color}{status}{Colors.RESET}")
            if result['latency']:
                latency_color = Colors.SUCCESS if result['latency'] < 500 else Colors.WARNING
                print(f"   Latency: {latency_color}{result['latency']:.0f}ms{Colors.RESET}")
            if result['details']:
                print(f"   Details: {result['details']}")
            if result['errors']:
                print(f"   {Colors.ERROR}Errors: {', '.join(result['errors'])}{Colors.RESET}")
        
        print("\n" + "─" * 60)
        print(f"{Colors.SUCCESS}✅ Working: {working}{Colors.RESET}")
        print(f"{Colors.ERROR}❌ Failed: {failed}{Colors.RESET}")
        print(f"{Colors.WARNING}⚠️ Not Configured: {not_configured}{Colors.RESET}")
        print("─" * 60)
        
        # Troubleshooting tips
        if failed > 0 or not_configured > 0:
            self.print_section("🔧 TROUBLESHOOTING TIPS")
            
            if self.results['google']['status'] != '✅ WORKING':
                print(f"\n{Colors.INFO}Google Safe Browsing:{Colors.RESET}")
                print("  • Enable the API at: https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com")
                print("  • Check if billing is enabled (even free tier requires billing account)")
                print("  • Verify API key restrictions (IP, HTTP referrer, etc.)")
            
            if self.results['virustotal']['status'] != '✅ WORKING':
                print(f"\n{Colors.INFO}VirusTotal:{Colors.RESET}")
                print("  • Check API key at: https://www.virustotal.com/gui/user/API_KEY")
                print("  • Verify daily quota (free tier: 500 requests/day)")
                print("  • Public API keys start with a 64-character alphanumeric string")
            
            if self.results['ipqs']['status'] != '✅ WORKING':
                print(f"\n{Colors.INFO}IPQualityScore:{Colors.RESET}")
                print("  • Get API key from: https://www.ipqualityscore.com/user/settings")
                print("  • Check if account is active and has quota remaining")
                print("  • Free tier allows 5,000 requests/month")
        
        return working, failed, not_configured

def check_env_file() -> Dict[str, Any]:
    """Enhanced environment file checking"""
    env_status = {
        'exists': False,
        'google': False,
        'virustotal': False,
        'ipqs': False,
        'placeholders': []
    }
    
    print(f"\n{Colors.INFO}📁 Checking environment configuration...{Colors.RESET}")
    
    if not os.path.exists('.env'):
        print(f"{Colors.ERROR}❌ .env file not found!{Colors.RESET}")
        return env_status
    
    env_status['exists'] = True
    print(f"{Colors.SUCCESS}✅ .env file found{Colors.RESET}")
    
    # Load and check keys
    with open('.env', 'r') as f:
        content = f.read()
    
    # Check Google key
    google_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    if google_key and google_key != 'your_google_api_key_here':
        env_status['google'] = True
        print(f"{Colors.SUCCESS}   ✅ Google API key: Configured{Colors.RESET}")
    else:
        env_status['placeholders'].append('google')
        print(f"{Colors.WARNING}   ⚠️ Google API key: Not configured{Colors.RESET}")
    
    # Check VirusTotal key
    vt_key = os.getenv('VIRUSTOTAL_API_KEY')
    if vt_key and vt_key != 'your_virustotal_api_key_here':
        env_status['virustotal'] = True
        print(f"{Colors.SUCCESS}   ✅ VirusTotal key: Configured{Colors.RESET}")
    else:
        env_status['placeholders'].append('virustotal')
        print(f"{Colors.WARNING}   ⚠️ VirusTotal key: Not configured{Colors.RESET}")
    
    # Check IPQS key
    ipqs_key = os.getenv('IPQUALITYSCORE_API_KEY')
    if ipqs_key and ipqs_key != 'your_ipqs_api_key_here':
        env_status['ipqs'] = True
        print(f"{Colors.SUCCESS}   ✅ IPQualityScore key: Configured{Colors.RESET}")
    else:
        env_status['placeholders'].append('ipqs')
        print(f"{Colors.WARNING}   ⚠️ IPQualityScore key: Not configured{Colors.RESET}")
    
    return env_status

def create_env_template():
    """Create enhanced .env template"""
    if not os.path.exists('.env'):
        template = """# ========================================
# API Keys for Phishing URL Detector
# Get these from respective services
# ========================================

# Google Safe Browsing API
# Get from: https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key_here

# VirusTotal API
# Get from: https://www.virustotal.com/gui/user/YOUR_USERNAME/api-key
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# IPQualityScore API
# Get from: https://www.ipqualityscore.com/user/settings
IPQUALITYSCORE_API_KEY=your_ipqs_api_key_here

# ========================================
# Application Configuration
# ========================================
SECRET_KEY=your-secret-key-change-this-in-production
DEBUG=True
REDIS_URL=redis://localhost:6379
"""
        with open('.env', 'w') as f:
            f.write(template)
        print(f"{Colors.SUCCESS}✅ Created .env file with template{Colors.RESET}")
        print(f"{Colors.INFO}📝 Please edit .env and add your actual API keys{Colors.RESET}")
    else:
        print(f"{Colors.WARNING}⚠️ .env file already exists{Colors.RESET}")

def interactive_mode():
    """Interactive mode for testing and updating keys"""
    print(f"\n{Colors.HEADER}🔧 Interactive API Key Manager{Colors.RESET}")
    print("1. Test all API keys")
    print("2. Test single API key")
    print("3. Update API key")
    print("4. View current configuration")
    print("5. Exit")
    
    choice = input(f"\n{Colors.INFO}Select option (1-5): {Colors.RESET}").strip()
    
    tester = EnhancedAPITester(verbose=True)
    
    if choice == '1':
        tester.run_all_tests()
    elif choice == '2':
        print("\nAvailable APIs:")
        print("1. Google Safe Browsing")
        print("2. VirusTotal")
        print("3. IPQualityScore")
        api_choice = input("Select API (1-3): ").strip()
        
        api_map = {'1': 'google', '2': 'virustotal', '3': 'ipqs'}
        if api_choice in api_map:
            tester.run_single_test(api_map[api_choice])
        else:
            print(f"{Colors.ERROR}Invalid choice{Colors.RESET}")
    elif choice == '3':
        print("\nUpdate API key:")
        print("1. Google Safe Browsing")
        print("2. VirusTotal")
        print("3. IPQualityScore")
        api_choice = input("Select API (1-3): ").strip()
        
        api_map = {'1': 'google', '2': 'virustotal', '3': 'ipqs'}
        key_map = {
            'google': 'GOOGLE_SAFE_BROWSING_API_KEY',
            'virustotal': 'VIRUSTOTAL_API_KEY',
            'ipqs': 'IPQUALITYSCORE_API_KEY'
        }
        
        if api_choice in api_map:
            api_name = api_map[api_choice]
            new_key = input(f"Enter new {api_name} API key: ").strip()
            if new_key:
                set_key('.env', key_map[api_name], new_key)
                print(f"{Colors.SUCCESS}✅ API key updated{Colors.RESET}")
                # Test the new key
                print(f"\n{Colors.INFO}Testing new key...{Colors.RESET}")
                tester.run_single_test(api_name)
            else:
                print(f"{Colors.ERROR}No key entered{Colors.RESET}")
        else:
            print(f"{Colors.ERROR}Invalid choice{Colors.RESET}")
    elif choice == '4':
        check_env_file()
    else:
        return False
    
    return True

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(description='Enhanced API Key Tester for Phishing URL Detector')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-g', '--google', action='store_true', help='Test only Google API')
    parser.add_argument('-vt', '--virustotal', action='store_true', help='Test only VirusTotal')
    parser.add_argument('-i', '--ipqs', action='store_true', help='Test only IPQualityScore')
    parser.add_argument('-s', '--save', action='store_true', help='Save results to file')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Request timeout in seconds')
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('--create-env', action='store_true', help='Create .env template file')
    
    args = parser.parse_args()
    
    if args.create_env:
        create_env_template()
        return
    
    if args.interactive:
        while interactive_mode():
            print("\n" + "─" * 40)
        return
    
    # Regular mode
    print(f"\n{Colors.BOLD}{'🔐' * 30}{Colors.RESET}")
    print(f"{Colors.HEADER}         ENHANCED API KEY VALIDATION TOOL v2.0{Colors.RESET}")
    print(f"{Colors.BOLD}{'🔐' * 30}{Colors.RESET}")
    
    # Check environment
    env_status = check_env_file()
    
    if not env_status['exists']:
        create = input(f"\n{Colors.WARNING}Create .env file? (y/n): {Colors.RESET}").lower()
        if create == 'y':
            create_env_template()
            print(f"\n{Colors.INFO}Please edit .env with your API keys and run again{Colors.RESET}")
            return
    
    # Create tester instance
    tester = EnhancedAPITester(verbose=args.verbose, timeout=args.timeout)
    
    # Run specified tests or all
    if args.google:
        tester.test_google_safe_browsing()
    elif args.virustotal:
        tester.test_virustotal()
    elif args.ipqs:
        tester.test_ipqualityscore()
    else:
        tester.run_all_tests()
    
    # Save results if requested
    if args.save:
        tester.save_results_to_file()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}\n⚠️ Test cancelled by user{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.ERROR}❌ Unexpected error: {e}{Colors.RESET}")
        sys.exit(1)