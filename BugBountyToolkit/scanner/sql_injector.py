"""
SQL Injection Scanner Module
Provides functionality to test for SQL injection vulnerabilities
"""

import requests
import time
import re
import threading
import json
from urllib.parse import urljoin, urlparse, parse_qs, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from utils.logger import Logger
from utils.proxy import ProxyManager


class SQLInjector:
    """SQL Injection vulnerability scanner"""
    
    def __init__(self, target_url, payloads_file="payloads/sqli.txt", use_proxy=False, max_threads=5, save=False):
        """
        Initialize SQL Injector
        
        Args:
            target_url (str): Target URL to test
            payloads_file (str): Path to SQL injection payloads file
            use_proxy (bool/dict): Whether to use proxy for requests, or proxy dict for Burp
            max_threads (int): Maximum number of threads to use
            save (bool): Whether to save results to logs
        """
        self.target_url = target_url
        self.payloads_file = payloads_file
        self.use_proxy = use_proxy
        self.max_threads = max_threads
        self.save = save
        self.logger = Logger("sql_injector")
        self.results_lock = threading.Lock()
        self.vulnerable_payloads = []
        
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
        
        # SQL error patterns for different databases
        self.error_patterns = {
            'mysql': [
                r'mysql_fetch',
                r'mysql_query',
                r'mysql_num_rows',
                r'warning:.*mysql',
                r'you have an error in your sql syntax',
                r'supplied argument is not a valid mysql',
                r'mysql server version for the right syntax'
            ],
            'postgresql': [
                r'postgresql.*error',
                r'warning:.*\Wpg_',
                r'valid postgresql result',
                r'npgsql\.',
                r'pg_query\(\)',
                r'pg_exec\(\)'
            ],
            'mssql': [
                r'microsoft jet database',
                r'odbc microsoft access',
                r'microsoft ole db provider',
                r'unclosed quotation mark',
                r'microsoft sql server',
                r'\[sql server\]',
                r'\[microsoft\]\[odbc sql server driver\]'
            ],
            'oracle': [
                r'ora-\d+',
                r'oracle error',
                r'oracle.*driver',
                r'warning.*\Woci_',
                r'warning.*\Wora_'
            ],
            'sqlite': [
                r'sqlite_master',
                r'sqlite_temp_master',
                r'sqlite3.operationalerror',
                r'sqlite3.databaseerror',
                r'sqlite warning'
            ]
        }
        
    def _load_payloads(self):
        """Load SQL injection payloads from file"""
        try:
            with open(self.payloads_file, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            # Categorize payloads for different attack types
            categorized_payloads = {
                'error_based': [],
                'boolean_based': [],
                'time_based': [],
                'union_based': []
            }
            
            for payload in payloads:
                payload_lower = payload.lower()
                
                # Categorize payloads based on content
                if any(keyword in payload_lower for keyword in ['sleep', 'waitfor', 'benchmark', 'pg_sleep']):
                    categorized_payloads['time_based'].append(payload)
                elif any(keyword in payload_lower for keyword in ['union', 'select']):
                    categorized_payloads['union_based'].append(payload)
                elif any(keyword in payload_lower for keyword in ['and', 'or']) and any(op in payload for op in ['=', '>', '<']):
                    categorized_payloads['boolean_based'].append(payload)
                else:
                    categorized_payloads['error_based'].append(payload)
            
            self.logger.info(f"Loaded {len(payloads)} payloads - "
                           f"Error: {len(categorized_payloads['error_based'])}, "
                           f"Boolean: {len(categorized_payloads['boolean_based'])}, "
                           f"Time: {len(categorized_payloads['time_based'])}, "
                           f"Union: {len(categorized_payloads['union_based'])}")
            
            return categorized_payloads
            
        except FileNotFoundError:
            self.logger.error(f"Payloads file {self.payloads_file} not found")
            return {'error_based': [], 'boolean_based': [], 'time_based': [], 'union_based': []}
    
    def _make_request(self, method, url, params=None, data=None, timeout=10):
        """
        Make HTTP request with proxy configuration
        
        Args:
            method (str): HTTP method (GET/POST)
            url (str): Target URL
            params (dict): URL parameters for GET
            data (dict): POST data
            timeout (int): Request timeout
            
        Returns:
            requests.Response: HTTP response object
        """
        try:
            if self.proxy_config:
                # Use direct proxy configuration (Burp)
                proxies = self.proxy_config
            elif self.proxy_manager:
                # Use proxy manager
                proxies = self.proxy_manager.get_proxy()
            else:
                proxies = None
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            if method.upper() == 'GET':
                response = requests.get(url, params=params, proxies=proxies, 
                                      headers=headers, timeout=timeout)
            elif method.upper() == 'POST':
                response = requests.post(url, data=data, proxies=proxies, 
                                       headers=headers, timeout=timeout)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            return response
            
        except Exception as e:
            self.logger.error(f"Request failed: {str(e)}")
            raise
    
    def _detect_error_based_sqli(self, response_text):
        """
        Detect error-based SQL injection by checking for database error messages
        
        Args:
            response_text (str): HTTP response text
            
        Returns:
            tuple: (is_vulnerable, detected_database, error_message)
        """
        response_lower = response_text.lower()
        
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, response_lower, re.IGNORECASE)
                if match:
                    return True, db_type, match.group(0)
        
        return False, None, None
    
    def _detect_boolean_based_sqli(self, original_response, true_response, false_response):
        """
        Detect boolean-based SQL injection by comparing response differences
        
        Args:
            original_response (str): Original response content
            true_response (str): Response with 'true' condition payload
            false_response (str): Response with 'false' condition payload
            
        Returns:
            bool: True if boolean-based SQLi detected
        """
        # Compare response lengths
        orig_len = len(original_response)
        true_len = len(true_response)
        false_len = len(false_response)
        
        # Check for significant differences
        if abs(true_len - orig_len) < 50 and abs(false_len - orig_len) > 100:
            return True
        
        if abs(true_len - false_len) > 100:
            return True
        
        # Check for content differences
        true_words = set(true_response.split())
        false_words = set(false_response.split())
        
        # If responses have significantly different word counts
        if abs(len(true_words) - len(false_words)) > 10:
            return True
        
        return False
    
    def _detect_time_based_sqli(self, response_time, baseline_time, delay_time=5):
        """
        Detect time-based SQL injection by checking response time delay
        
        Args:
            response_time (float): Response time for payload request
            baseline_time (float): Baseline response time
            delay_time (int): Expected delay time in seconds
            
        Returns:
            bool: True if time-based SQLi detected
        """
        # Check if response time is significantly longer than baseline
        time_diff = response_time - baseline_time
        
        # Allow for some network variance (50% of expected delay)
        threshold = delay_time * 0.5
        
        return time_diff >= threshold
    
    def _detect_union_based_sqli(self, response_text, payload):
        """
        Detect UNION-based SQL injection by checking for successful UNION queries
        
        Args:
            response_text (str): HTTP response text
            payload (str): UNION payload used
            
        Returns:
            bool: True if UNION-based SQLi detected
        """
        # Look for signs of successful UNION injection
        union_indicators = [
            r'union.*select.*from',
            r'select.*union.*select',
            r'information_schema',
            r'table_name.*from.*information_schema',
            r'column_name.*from.*information_schema'
        ]
        
        response_lower = response_text.lower()
        
        for indicator in union_indicators:
            if re.search(indicator, response_lower, re.IGNORECASE):
                return True
        
        # Check for extra columns in response (common with UNION attacks)
        if 'union' in payload.lower() and len(response_text) > 1000:
            # Look for repeated patterns that might indicate injected data
            words = response_text.split()
            if len(set(words)) != len(words):  # Duplicate words might indicate injection
                return True
        
        return False
    
    def test_parameter_with_payload(self, param_name, param_value, payload, attack_type, method='GET'):
        """
        Test a specific parameter with a specific payload
        
        Args:
            param_name (str): Parameter name
            param_value (str): Original parameter value
            payload (str): SQL injection payload
            attack_type (str): Type of attack (error_based, boolean_based, etc.)
            method (str): HTTP method (GET/POST)
            
        Returns:
            dict: Vulnerability information if found, None otherwise
        """
        try:
            vulnerability = None
            
            if attack_type == 'error_based':
                vulnerability = self._test_error_based(param_name, param_value, payload, method)
            elif attack_type == 'boolean_based':
                vulnerability = self._test_boolean_based(param_name, param_value, payload, method)
            elif attack_type == 'time_based':
                vulnerability = self._test_time_based(param_name, param_value, payload, method)
            elif attack_type == 'union_based':
                vulnerability = self._test_union_based(param_name, param_value, payload, method)
            
            if vulnerability:
                # Add to vulnerable payloads list and print to terminal
                with self.results_lock:
                    self.vulnerable_payloads.append(vulnerability)
                
                # Print vulnerable payload to terminal
                self._print_vulnerability(vulnerability)
                
                self.logger.info(f"SQL injection found: {attack_type} in parameter '{param_name}'")
            
            return vulnerability
            
        except Exception as e:
            self.logger.error(f"Error testing parameter {param_name} with {attack_type}: {str(e)}")
            return None
    
    def _test_error_based(self, param_name, param_value, payload, method):
        """Test for error-based SQL injection"""
        test_value = param_value + payload
        
        if method.upper() == 'GET':
            test_params = {param_name: test_value}
            response = self._make_request('GET', self.target_url, params=test_params)
        else:
            test_data = {param_name: test_value}
            response = self._make_request('POST', self.target_url, data=test_data)
        
        is_vulnerable, db_type, error_msg = self._detect_error_based_sqli(response.text)
        
        if is_vulnerable:
            return {
                'type': 'Error-based SQL Injection',
                'attack_type': 'error_based',
                'parameter': param_name,
                'payload': payload,
                'url': response.url,
                'method': method,
                'status_code': response.status_code,
                'database_type': db_type,
                'error_message': error_msg[:200],  # Truncate long errors
                'confidence': 'High'
            }
        
        return None
    
    def _test_boolean_based(self, param_name, param_value, payload, method):
        """Test for boolean-based SQL injection"""
        # Test with original value
        if method.upper() == 'GET':
            orig_response = self._make_request('GET', self.target_url, params={param_name: param_value})
        else:
            orig_response = self._make_request('POST', self.target_url, data={param_name: param_value})
        
        # Test with 'true' condition
        true_payload = param_value + payload
        if method.upper() == 'GET':
            true_response = self._make_request('GET', self.target_url, params={param_name: true_payload})
        else:
            true_response = self._make_request('POST', self.target_url, data={param_name: true_payload})
        
        # Test with 'false' condition
        false_payload = param_value + payload.replace('1=1', '1=2')
        if method.upper() == 'GET':
            false_response = self._make_request('GET', self.target_url, params={param_name: false_payload})
        else:
            false_response = self._make_request('POST', self.target_url, data={param_name: false_payload})
        
        if self._detect_boolean_based_sqli(orig_response.text, true_response.text, false_response.text):
            return {
                'type': 'Boolean-based SQL Injection',
                'attack_type': 'boolean_based',
                'parameter': param_name,
                'payload': payload,
                'url': true_response.url,
                'method': method,
                'status_code': true_response.status_code,
                'confidence': 'Medium'
            }
        
        return None
    
    def _test_time_based(self, param_name, param_value, payload, method):
        """Test for time-based SQL injection"""
        # Get baseline response time
        start_time = time.time()
        if method.upper() == 'GET':
            baseline_response = self._make_request('GET', self.target_url, params={param_name: param_value})
        else:
            baseline_response = self._make_request('POST', self.target_url, data={param_name: param_value})
        baseline_time = time.time() - start_time
        
        # Test with time-based payload
        test_value = param_value + payload
        start_time = time.time()
        if method.upper() == 'GET':
            test_response = self._make_request('GET', self.target_url, params={param_name: test_value}, timeout=15)
        else:
            test_response = self._make_request('POST', self.target_url, data={param_name: test_value}, timeout=15)
        test_time = time.time() - start_time
        
        if self._detect_time_based_sqli(test_time, baseline_time):
            return {
                'type': 'Time-based SQL Injection',
                'attack_type': 'time_based',
                'parameter': param_name,
                'payload': payload,
                'url': test_response.url,
                'method': method,
                'status_code': test_response.status_code,
                'response_time': f"{test_time:.2f}s",
                'baseline_time': f"{baseline_time:.2f}s",
                'confidence': 'High'
            }
        
        return None
    
    def _test_union_based(self, param_name, param_value, payload, method):
        """Test for UNION-based SQL injection"""
        test_value = param_value + payload
        
        if method.upper() == 'GET':
            test_params = {param_name: test_value}
            response = self._make_request('GET', self.target_url, params=test_params)
        else:
            test_data = {param_name: test_value}
            response = self._make_request('POST', self.target_url, data=test_data)
        
        if self._detect_union_based_sqli(response.text, payload):
            return {
                'type': 'UNION-based SQL Injection',
                'attack_type': 'union_based',
                'parameter': param_name,
                'payload': payload,
                'url': response.url,
                'method': method,
                'status_code': response.status_code,
                'confidence': 'High'
            }
        
        return None
    
    def _print_vulnerability(self, vulnerability):
        """Print vulnerability details to terminal"""
        print(f"\n🚨 VULNERABILITY FOUND!")
        print(f"{'='*50}")
        print(f"Type: {vulnerability['type']}")
        print(f"Parameter: {vulnerability['parameter']}")
        print(f"Method: {vulnerability['method']}")
        print(f"Payload: {vulnerability['payload']}")
        print(f"URL: {vulnerability['url']}")
        print(f"Confidence: {vulnerability['confidence']}")
        
        if 'database_type' in vulnerability:
            print(f"Database: {vulnerability['database_type'].upper()}")
        if 'error_message' in vulnerability:
            print(f"Error: {vulnerability['error_message']}")
        if 'response_time' in vulnerability:
            print(f"Response Time: {vulnerability['response_time']} (Baseline: {vulnerability['baseline_time']})")
        
        print(f"{'='*50}\n")
    
    def test_parameter(self, param_name, param_value, methods=['GET', 'POST']):
        """
        Test a specific parameter for SQL injection using all attack types
        
        Args:
            param_name (str): Parameter name
            param_value (str): Original parameter value
            methods (list): HTTP methods to test (GET/POST)
            
        Returns:
            list: Found vulnerabilities
        """
        vulnerabilities = []
        
        # Test all attack types
        attack_types = ['error_based', 'boolean_based', 'time_based', 'union_based']
        
        for method in methods:
            for attack_type in attack_types:
                payloads = self.payloads.get(attack_type, [])
                
                if self.max_threads > 1:
                    # Use threading for payload testing
                    with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                        futures = []
                        
                        for payload in payloads:
                            future = executor.submit(
                                self.test_parameter_with_payload,
                                param_name, param_value, payload, attack_type, method
                            )
                            futures.append(future)
                        
                        # Collect results
                        for future in as_completed(futures):
                            try:
                                result = future.result()
                                if result:
                                    vulnerabilities.append(result)
                            except Exception as e:
                                self.logger.error(f"Thread error: {str(e)}")
                else:
                    # Sequential testing
                    for payload in payloads:
                        try:
                            result = self.test_parameter_with_payload(
                                param_name, param_value, payload, attack_type, method
                            )
                            if result:
                                vulnerabilities.append(result)
                            
                            # Rate limiting
                            time.sleep(0.1)
                            
                        except Exception as e:
                            self.logger.error(f"Error testing payload: {str(e)}")
        
    def test_parameter_with_payload(self, param_name, param_value, payload, attack_type, method):
        """
        Test a specific parameter with a specific payload
        
        Args:
            param_name (str): Parameter name
            param_value (str): Original parameter value
            payload (str): SQL injection payload
            attack_type (str): Type of attack (error_based, boolean_based, etc.)
            method (str): HTTP method (GET/POST)
            
        Returns:
            dict: Vulnerability details if found, None otherwise
        """
        try:
            # Prepare test data
            test_value = payload
            
            if method.upper() == 'GET':
                test_params = {param_name: test_value}
                response = self._make_request('GET', self.target_url, params=test_params)
            else:
                test_data = {param_name: test_value}
                response = self._make_request('POST', self.target_url, data=test_data)
            
            if not response:
                return None
            
            # Check based on attack type
            is_vulnerable = False
            
            if attack_type == 'error_based':
                is_vulnerable = self._detect_error_based(response)
            elif attack_type == 'boolean_based':
                # For boolean-based, we need to compare with original response
                original_response = self._make_request(method, self.target_url, params={param_name: param_value} if method == 'GET' else None,
                                                    data={param_name: param_value} if method == 'POST' else None)
                is_vulnerable = self._detect_boolean_based(response, original_response)
            elif attack_type == 'time_based':
                is_vulnerable = self._detect_time_based(response)
            elif attack_type == 'union_based':
                is_vulnerable = self._detect_union_based(response)
            
            if is_vulnerable:
                return {
                    'type': f'SQL Injection ({attack_type.replace("_", " ").title()})',
                    'parameter': param_name,
                    'payload': payload,
                    'method': method,
                    'url': response.url,
                    'status_code': response.status_code,
                    'attack_type': attack_type
                }
                
        except Exception as e:
            self.logger.error(f"Error testing {param_name} with {attack_type} payload: {str(e)}")
            
        return None

    def scan(self):
        """
        Main scanning method - orchestrates the entire SQL injection scan
        
        Returns:
            dict: Scan results including vulnerabilities found
        """
        self.logger.info(f"Starting SQL injection scan on: {self.target_url}")
        print(f"\n{Fore.CYAN}[INFO]{Style.RESET_ALL} Starting SQL injection scan...")
        print(f"{Fore.YELLOW}Target:{Style.RESET_ALL} {self.target_url}")
        print(f"{Fore.YELLOW}Threads:{Style.RESET_ALL} {self.max_threads}")
        print(f"{Fore.YELLOW}Total Payloads:{Style.RESET_ALL} {sum(len(payloads) for payloads in self.payloads.values())}")
        
        all_vulnerabilities = []
        
        try:
            # Parse forms and extract parameters
            self.logger.info("Parsing target for parameters...")
            print(f"\n{Fore.CYAN}[INFO]{Style.RESET_ALL} Parsing target for parameters...")
            
            # Get initial response to parse forms
            response = self._make_request('GET', self.target_url)
            if not response:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Cannot access target URL")
                return {'vulnerabilities': [], 'error': 'Cannot access target URL'}
            
            # Parse forms using FormParser
            forms = self.form_parser.parse_forms(response.text)
            
            # Extract URL parameters
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(self.target_url)
            url_params = parse_qs(parsed_url.query)
            
            # Test URL parameters
            if url_params:
                print(f"{Fore.GREEN}[FOUND]{Style.RESET_ALL} {len(url_params)} URL parameters")
                for param_name, param_values in url_params.items():
                    param_value = param_values[0] if param_values else ""
                    print(f"  Testing parameter: {param_name}")
                    
                    vulnerabilities = self.test_parameter(param_name, param_value, ['GET'])
                    all_vulnerabilities.extend(vulnerabilities)
            
            # Test form parameters
            if forms:
                print(f"{Fore.GREEN}[FOUND]{Style.RESET_ALL} {len(forms)} forms")
                for i, form in enumerate(forms):
                    print(f"  Testing form {i+1}: {form.get('action', 'No action')}")
                    
                    for field in form.get('fields', []):
                        field_name = field.get('name')
                        field_value = field.get('value', 'test')
                        
                        if field_name:
                            print(f"    Testing field: {field_name}")
                            vulnerabilities = self.test_parameter(field_name, field_value, ['POST'])
                            all_vulnerabilities.extend(vulnerabilities)
            
            # Display results
            print(f"\n{Fore.CYAN}[SCAN COMPLETE]{Style.RESET_ALL}")
            if all_vulnerabilities:
                print(f"{Fore.RED}[VULNERABILITIES FOUND]{Style.RESET_ALL} {len(all_vulnerabilities)} SQL injection vulnerabilities detected:")
                for vuln in all_vulnerabilities:
                    self._print_vulnerability(vuln)
            else:
                print(f"{Fore.GREEN}[CLEAN]{Style.RESET_ALL} No SQL injection vulnerabilities found")
            
            # Save results if requested
            results = {
                'target_url': self.target_url,
                'vulnerabilities': all_vulnerabilities,
                'scan_date': datetime.now().isoformat(),
                'total_payloads_tested': sum(len(payloads) for payloads in self.payloads.values()),
                'threads_used': self.max_threads
            }
            
            if self.save_results:
                self._save_results(results)
            
            return results
            
        except Exception as e:
            error_msg = f"Scan error: {str(e)}"
            self.logger.error(error_msg)
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {error_msg}")
            return {'vulnerabilities': [], 'error': error_msg}

    def _save_results(self, results):
        """
        Save scan results to file
        
        Args:
            results (dict): Scan results to save
        """
        try:
            # Create logs directory if it doesn't exist
            logs_dir = Path(__file__).parent.parent / 'logs'
            logs_dir.mkdir(exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sql_injection_scan_{timestamp}.json"
            filepath = logs_dir / filename
            
            # Save results
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"{Fore.GREEN}[SAVED]{Style.RESET_ALL} Results saved to: {filepath}")
            self.logger.info(f"Results saved to: {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Could not save results: {str(e)}")

    
    def _check_sql_errors(self, response_text):
        """
        Check response for SQL error indicators
        
        Args:
            response_text (str): HTTP response text
            
        Returns:
            bool: True if SQL errors found
        """
        sql_errors = [
            'sql syntax',
            'mysql_fetch',
            'ora-',
            'microsoft jet database',
            'sqlite_master',
            'postgresql error',
            'warning: mysql',
            'valid mysql result',
            'mysqlclient'
        ]
        
        response_lower = response_text.lower()
        return any(error in response_lower for error in sql_errors)
    
    def scan(self, parameters=None):
        """
        Perform comprehensive SQL injection scan
        
        Args:
            parameters (dict): Parameters to test (if None, will attempt to detect forms)
            
        Returns:
            list: All found vulnerabilities
        """
        self.logger.info(f"Starting SQL injection scan on {self.target_url}")
        all_vulnerabilities = []
        
        if parameters:
            for param_name, param_value in parameters.items():
                vulns = self.test_parameter(param_name, param_value)
                all_vulnerabilities.extend(vulns)
        else:
            # Try to detect forms and test common parameters
            common_params = ['id', 'user', 'page', 'category', 'item', 'article', 'search']
            for param in common_params:
                vulns = self.test_parameter(param, "1")
                all_vulnerabilities.extend(vulns)
        
        self.logger.info(f"SQL injection scan completed. Found {len(all_vulnerabilities)} vulnerabilities")
        return all_vulnerabilities
