"""
XSS (Cross-Site Scripting) Scanner Module
Provides functionality to test for XSS vulnerabilities
"""

import requests
import time
from urllib.parse import urljoin, quote
from utils.logger import Logger
from utils.proxy import ProxyManager


class XSSScanner:
    """Cross-Site Scripting vulnerability scanner"""
    
    def __init__(self, target_url, payloads_file="payloads/xss.txt", use_proxy=False):
        """
        Initialize XSS Scanner
        
        Args:
            target_url (str): Target URL to test
            payloads_file (str): Path to XSS payloads file
            use_proxy (bool/dict): Whether to use proxy for requests, or proxy dict for Burp
        """
        self.target_url = target_url
        self.payloads_file = payloads_file
        self.use_proxy = use_proxy
        self.logger = Logger("xss_scanner")
        
        # Handle different proxy configurations
        if isinstance(use_proxy, dict):
            # Direct proxy configuration (e.g., Burp Suite)
            self.proxy_config = use_proxy
            self.proxy_manager = None
        elif use_proxy:
            # Use proxy manager
            self.proxy_manager = ProxyManager()
            self.proxy_config = None
        else:
            self.proxy_manager = None
            self.proxy_config = None
            
        self.payloads = self._load_payloads()
        
    def _load_payloads(self):
        """Load XSS payloads from file"""
        try:
            with open(self.payloads_file, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            self.logger.error(f"Payloads file {self.payloads_file} not found")
            return []
    
    def test_parameter(self, param_name, param_value, method='GET'):
        """
        Test a specific parameter for XSS
        
        Args:
            param_name (str): Parameter name
            param_value (str): Original parameter value
            method (str): HTTP method (GET/POST)
            
        Returns:
            list: Found vulnerabilities
        """
        vulnerabilities = []
        
        for payload in self.payloads:
            try:
                # Prepare payload
                test_value = param_value + payload
                
                # Make request based on method
                if self.proxy_config:
                    # Use direct proxy configuration (Burp)
                    proxies = self.proxy_config
                elif self.proxy_manager:
                    # Use proxy manager
                    proxies = self.proxy_manager.get_proxy()
                else:
                    proxies = None
                
                if method.upper() == 'GET':
                    test_params = {param_name: test_value}
                    response = requests.get(
                        self.target_url,
                        params=test_params,
                        proxies=proxies,
                        timeout=10
                    )
                else:
                    test_data = {param_name: test_value}
                    response = requests.post(
                        self.target_url,
                        data=test_data,
                        proxies=proxies,
                        timeout=10
                    )
                
                # Check if payload is reflected in response
                if self._check_xss_reflection(payload, response.text):
                    vulnerability = {
                        'type': 'XSS (Cross-Site Scripting)',
                        'parameter': param_name,
                        'payload': payload,
                        'url': response.url,
                        'method': method,
                        'status_code': response.status_code,
                        'reflection_type': self._get_reflection_type(payload, response.text)
                    }
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"XSS vulnerability found in parameter: {param_name}")
                
                # Rate limiting
                time.sleep(0.5)
                
            except Exception as e:
                self.logger.error(f"Error testing parameter {param_name}: {str(e)}")
        
        return vulnerabilities
    
    def _check_xss_reflection(self, payload, response_text):
        """
        Check if XSS payload is reflected in response
        
        Args:
            payload (str): XSS payload
            response_text (str): HTTP response text
            
        Returns:
            bool: True if payload is reflected
        """
        # Check for direct reflection
        if payload in response_text:
            return True
        
        # Check for HTML entity encoded reflection
        import html
        encoded_payload = html.escape(payload)
        if encoded_payload in response_text:
            return True
        
        # Check for URL encoded reflection
        url_encoded = quote(payload)
        if url_encoded in response_text:
            return True
        
        return False
    
    def _get_reflection_type(self, payload, response_text):
        """
        Determine the type of reflection (direct, encoded, etc.)
        
        Args:
            payload (str): XSS payload
            response_text (str): HTTP response text
            
        Returns:
            str: Type of reflection
        """
        if payload in response_text:
            return "Direct"
        
        import html
        if html.escape(payload) in response_text:
            return "HTML Encoded"
        
        if quote(payload) in response_text:
            return "URL Encoded"
        
        return "Unknown"
    
    def test_forms(self):
        """
        Automatically detect and test forms on the target page
        
        Returns:
            list: Found vulnerabilities
        """
        from utils.form_parser import FormParser
        
        vulnerabilities = []
        try:
            # Get the target page
            response = requests.get(self.target_url, timeout=10)
            
            # Parse forms
            form_parser = FormParser()
            forms = form_parser.parse_forms(response.text, self.target_url)
            
            # Test each form
            for form in forms:
                self.logger.info(f"Testing form: {form['action']}")
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'search', 'email', 'url']:
                        vulns = self.test_parameter(
                            input_field['name'],
                            input_field.get('value', ''),
                            form['method']
                        )
                        vulnerabilities.extend(vulns)
        
        except Exception as e:
            self.logger.error(f"Error testing forms: {str(e)}")
        
        return vulnerabilities
    
    def scan(self, parameters=None, test_forms=True):
        """
        Perform comprehensive XSS scan
        
        Args:
            parameters (dict): Specific parameters to test
            test_forms (bool): Whether to automatically test forms
            
        Returns:
            list: All found vulnerabilities
        """
        self.logger.info(f"Starting XSS scan on {self.target_url}")
        all_vulnerabilities = []
        
        # Test specific parameters if provided
        if parameters:
            for param_name, param_value in parameters.items():
                vulns = self.test_parameter(param_name, param_value)
                all_vulnerabilities.extend(vulns)
        
        # Test forms automatically
        if test_forms:
            form_vulns = self.test_forms()
            all_vulnerabilities.extend(form_vulns)
        
        # Test common parameters if no specific parameters provided
        if not parameters and not test_forms:
            common_params = ['q', 'search', 'query', 'name', 'comment', 'message']
            for param in common_params:
                vulns = self.test_parameter(param, "test")
                all_vulnerabilities.extend(vulns)
        
        self.logger.info(f"XSS scan completed. Found {len(all_vulnerabilities)} vulnerabilities")
        return all_vulnerabilities
