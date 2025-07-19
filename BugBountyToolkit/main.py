#!/usr/bin/env python3
"""
BugBountyToolkit - Main Entry Point
A comprehensive security testing toolkit for bug bounty hunters and penetration testers
"""

import argparse
import sys
import json
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Add the current directory to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from scanner.sql_injector import SQLInjector
from scanner.xss_scanner import XSSScanner
from scanner.lfi_checker import LFIChecker
from utils.logger import Logger
from config import get_config, update_config


class BugBountyToolkit:
    """Main application class for BugBountyToolkit"""
    
    def __init__(self, use_burp=False, num_threads=1):
        """Initialize the toolkit"""
        self.config = get_config()
        self.logger = Logger("main")
        self.results = []
        self.use_burp = use_burp
        self.num_threads = num_threads
        self.results_lock = threading.Lock()
        
        # Configure Burp Suite proxy if requested
        if self.use_burp:
            self._configure_burp_proxy()
    
    def _configure_burp_proxy(self):
        """Configure Burp Suite proxy settings"""
        burp_proxy = {
            'http': 'http://localhost:8080',
            'https': 'http://localhost:8080'
        }
        self.config.set('burp_proxy', burp_proxy)
        self.config.set('use_burp', True)
        self.logger.info("Configured to route traffic through Burp Suite (localhost:8080)")
    
    def _get_proxy_config(self):
        """Get proxy configuration based on settings"""
        if self.use_burp:
            return self.config.get('burp_proxy')
        elif self.config.get('use_proxy'):
            return True  # Use proxy manager
        return False
    
    def run_sql_injection_scan(self, target_url, parameters=None):
        """
        Run SQL injection scan
        
        Args:
            target_url (str): Target URL to scan
            parameters (dict): Optional parameters to test
            
        Returns:
            list: Found vulnerabilities
        """
        self.logger.info("Starting SQL Injection scan")
        
        try:
            scanner = SQLInjector(
                target_url=target_url,
                use_proxy=self._get_proxy_config()
            )
            
            vulnerabilities = scanner.scan(parameters)
            
            with self.results_lock:
                self.results.extend(vulnerabilities)
            
            self.logger.info(f"SQL Injection scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"SQL Injection scan failed: {str(e)}")
            return []
    
    def run_xss_scan(self, target_url, parameters=None, test_forms=True):
        """
        Run XSS scan
        
        Args:
            target_url (str): Target URL to scan
            parameters (dict): Optional parameters to test
            test_forms (bool): Whether to test forms automatically
            
        Returns:
            list: Found vulnerabilities
        """
        self.logger.info("Starting XSS scan")
        
        try:
            scanner = XSSScanner(
                target_url=target_url,
                use_proxy=self._get_proxy_config()
            )
            
            vulnerabilities = scanner.scan(parameters, test_forms)
            
            with self.results_lock:
                self.results.extend(vulnerabilities)
            
            self.logger.info(f"XSS scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"XSS scan failed: {str(e)}")
            return []
    
    def run_lfi_scan(self, target_url, parameters=None):
        """
        Run LFI scan
        
        Args:
            target_url (str): Target URL to scan
            parameters (dict): Optional parameters to test
            
        Returns:
            list: Found vulnerabilities
        """
        self.logger.info("Starting LFI scan")
        
        try:
            scanner = LFIChecker(
                target_url=target_url,
                use_proxy=self._get_proxy_config()
            )
            
            vulnerabilities = scanner.scan(parameters)
            
            with self.results_lock:
                self.results.extend(vulnerabilities)
            
            self.logger.info(f"LFI scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"LFI scan failed: {str(e)}")
            return []
    
    def run_selected_scans(self, target_url, scan_types, parameters=None):
        """
        Run selected scans with threading support
        
        Args:
            target_url (str): Target URL to scan
            scan_types (list): List of scan types to run ['sqli', 'xss', 'lfi']
            parameters (dict): Optional parameters to test
            
        Returns:
            dict: Results from all requested scans
        """
        self.logger.info(f"Starting selected scans {scan_types} on {target_url}")
        
        results = {
            'target': target_url,
            'scan_types': scan_types,
            'sqli': [],
            'xss': [],
            'lfi': [],
            'total_vulnerabilities': 0
        }
        
        # Prepare scan functions
        scan_functions = []
        if 'sqli' in scan_types:
            scan_functions.append(('sqli', self.run_sql_injection_scan))
        if 'xss' in scan_types:
            scan_functions.append(('xss', self.run_xss_scan))
        if 'lfi' in scan_types:
            scan_functions.append(('lfi', self.run_lfi_scan))
        
        if not scan_functions:
            self.logger.warning("No valid scan types specified")
            return results
        
        # Run scans with threading
        if self.num_threads > 1 and len(scan_functions) > 1:
            self.logger.info(f"Running {len(scan_functions)} scans with {self.num_threads} threads")
            
            with ThreadPoolExecutor(max_workers=min(self.num_threads, len(scan_functions))) as executor:
                # Submit all scan tasks
                future_to_scan = {}
                for scan_type, scan_func in scan_functions:
                    future = executor.submit(scan_func, target_url, parameters)
                    future_to_scan[future] = scan_type
                
                # Collect results as they complete
                for future in as_completed(future_to_scan):
                    scan_type = future_to_scan[future]
                    try:
                        scan_results = future.result()
                        results[scan_type] = scan_results
                        self.logger.info(f"{scan_type.upper()} scan completed with {len(scan_results)} vulnerabilities")
                    except Exception as e:
                        self.logger.error(f"{scan_type.upper()} scan failed: {str(e)}")
                        results[scan_type] = []
        else:
            # Run scans sequentially
            self.logger.info("Running scans sequentially")
            for scan_type, scan_func in scan_functions:
                try:
                    scan_results = scan_func(target_url, parameters)
                    results[scan_type] = scan_results
                except Exception as e:
                    self.logger.error(f"{scan_type.upper()} scan failed: {str(e)}")
                    results[scan_type] = []
        
        # Calculate totals
        total_vulns = sum(len(results[scan_type]) for scan_type in ['sqli', 'xss', 'lfi'])
        results['total_vulnerabilities'] = total_vulns
        
        self.logger.info(f"All selected scans completed. Total vulnerabilities found: {total_vulns}")
        return results
    
    def run_comprehensive_scan(self, target_url, parameters=None):
        """
        Run all available scans on the target
        
        Args:
            target_url (str): Target URL to scan
            parameters (dict): Optional parameters to test
            
        Returns:
            dict: Results from all scans
        """
        self.logger.info(f"Starting comprehensive scan on {target_url}")
        
        all_results = {
            'target': target_url,
            'sqli': [],
            'xss': [],
            'lfi': [],
            'total_vulnerabilities': 0
        }
        
        # Run SQL Injection scan
        sqli_results = self.run_sql_injection_scan(target_url, parameters)
        all_results['sqli'] = sqli_results
        
        # Run XSS scan
        xss_results = self.run_xss_scan(target_url, parameters)
        all_results['xss'] = xss_results
        
        # Run LFI scan
        lfi_results = self.run_lfi_scan(target_url, parameters)
        all_results['lfi'] = lfi_results
        
        # Calculate totals
        all_results['total_vulnerabilities'] = len(sqli_results) + len(xss_results) + len(lfi_results)
        
        self.logger.info(f"Comprehensive scan completed. Total vulnerabilities found: {all_results['total_vulnerabilities']}")
        
        return all_results
    
    def save_results_to_log(self, results):
        """
        Save scan results to automatically generated log file (for --save flag)
        
        Args:
            results (dict/list): Scan results
            
        Returns:
            str: Path to saved file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_host = results.get('target', 'unknown').replace('://', '_').replace('/', '_').replace(':', '_')
        
        # Generate log filename
        log_filename = f"scan_results_{target_host}_{timestamp}.json"
        log_path = Path("logs") / log_filename
        
        # Ensure logs directory exists
        log_path.parent.mkdir(exist_ok=True)
        
        try:
            with open(log_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Results automatically saved to {log_path}")
            return str(log_path)
            
        except Exception as e:
            self.logger.error(f"Failed to save results to log file: {str(e)}")
            return None
    
    def save_results(self, results, output_file=None, format='json'):
        """
        Save scan results to automatically generated log file (for --save flag)
        
        Args:
            results (dict/list): Scan results
            
        Returns:
            str: Path to saved file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_host = results.get('target', 'unknown').replace('://', '_').replace('/', '_').replace(':', '_')
        
        # Generate log filename
        log_filename = f"scan_results_{target_host}_{timestamp}.json"
        log_path = Path("logs") / log_filename
        
        # Ensure logs directory exists
        log_path.parent.mkdir(exist_ok=True)
        
        try:
            with open(log_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Results automatically saved to {log_path}")
            return str(log_path)
            
        except Exception as e:
            self.logger.error(f"Failed to save results to log file: {str(e)}")
            return None
        """
        Save scan results to file
        
        Args:
            results (dict/list): Scan results
            output_file (str): Output file path
            format (str): Output format (json, csv, txt)
            
        Returns:
            str: Path to saved file
        """
        if not output_file:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"scan_results_{timestamp}.{format}"
        
        try:
            if format.lower() == 'json':
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
            
            elif format.lower() == 'txt':
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write("BugBountyToolkit - Scan Results\n")
                    f.write("=" * 50 + "\n\n")
                    
                    if isinstance(results, dict):
                        if 'target' in results:
                            f.write(f"Target: {results['target']}\n")
                            f.write(f"Total Vulnerabilities: {results.get('total_vulnerabilities', 0)}\n\n")
                        
                        for scan_type, vulns in results.items():
                            if scan_type in ['sqli', 'xss', 'lfi'] and vulns:
                                f.write(f"{scan_type.upper()} Vulnerabilities ({len(vulns)}):\n")
                                f.write("-" * 30 + "\n")
                                
                                for i, vuln in enumerate(vulns, 1):
                                    f.write(f"{i}. {vuln.get('type', 'Unknown')}\n")
                                    f.write(f"   Parameter: {vuln.get('parameter', 'N/A')}\n")
                                    f.write(f"   URL: {vuln.get('url', 'N/A')}\n")
                                    f.write(f"   Payload: {vuln.get('payload', 'N/A')[:100]}...\n")
                                    if 'confidence' in vuln:
                                        f.write(f"   Confidence: {vuln['confidence']}\n")
                                    f.write("\n")
                    
                    elif isinstance(results, list):
                        f.write(f"Found {len(results)} vulnerabilities:\n\n")
                        for i, vuln in enumerate(results, 1):
                            f.write(f"{i}. {vuln.get('type', 'Unknown')}\n")
                            for key, value in vuln.items():
                                if key != 'type':
                                    f.write(f"   {key.title()}: {value}\n")
                            f.write("\n")
            
            self.logger.info(f"Results saved to {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {str(e)}")
            return None
    
    def print_summary(self, results):
        """
        Print scan summary to console
        
        Args:
            results (dict/list): Scan results
        """
        print("\n" + "=" * 60)
        print("BugBountyToolkit - Scan Summary")
        print("=" * 60)
        
        if isinstance(results, dict) and 'target' in results:
            print(f"Target: {results['target']}")
            print(f"Total Vulnerabilities: {results.get('total_vulnerabilities', 0)}")
            print()
            
            for scan_type in ['sqli', 'xss', 'lfi']:
                vulns = results.get(scan_type, [])
                if vulns:
                    print(f"{scan_type.upper()} Vulnerabilities: {len(vulns)}")
                    for vuln in vulns[:3]:  # Show first 3
                        print(f"  - {vuln.get('type', 'Unknown')} in parameter '{vuln.get('parameter', 'N/A')}'")
                    if len(vulns) > 3:
                        print(f"  ... and {len(vulns) - 3} more")
                    print()
        
        elif isinstance(results, list):
            print(f"Total Vulnerabilities Found: {len(results)}")
            for vuln in results[:5]:  # Show first 5
                print(f"  - {vuln.get('type', 'Unknown')} in parameter '{vuln.get('parameter', 'N/A')}'")
            if len(results) > 5:
                print(f"  ... and {len(results) - 5} more")
        
        print("=" * 60)


def create_parser():
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="BugBountyToolkit - Comprehensive web security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url http://example.com --sqli --xss
  %(prog)s --url http://example.com --lfi --tor
  %(prog)s --url http://example.com --sqli --threads 5 --save
  %(prog)s --url http://example.com --xss --burp --save
        """
    )
    
    # Required target URL
    parser.add_argument('--url', required=True,
                        help='Target URL to scan')
    
    # Scanner options (at least one required)
    scanner_group = parser.add_argument_group('Scanner Options (at least one required)')
    scanner_group.add_argument('--sqli', action='store_true',
                               help='Run SQL injection scanner')
    scanner_group.add_argument('--xss', action='store_true',
                               help='Run XSS scanner')
    scanner_group.add_argument('--lfi', action='store_true',
                               help='Run LFI scanner')
    
    # Proxy and networking options
    proxy_group = parser.add_argument_group('Proxy Options')
    proxy_group.add_argument('--tor', action='store_true',
                             help='Enable Tor proxy for anonymity')
    proxy_group.add_argument('--burp', action='store_true',
                             help='Route traffic via Burp Suite (localhost:8080)')
    
    # Performance options
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument('--threads', type=int, default=1, metavar='N',
                            help='Number of threads to run (default: 1)')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--save', action='store_true',
                              help='Save results in log file')
    
    # Additional options
    parser.add_argument('-p', '--parameters',
                        help='Parameters to test (format: "param1=value1&param2=value2")')
    parser.add_argument('--delay', type=float, default=0.5,
                        help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet mode (minimal output)')
    
    return parser


def parse_parameters(param_string):
    """
    Parse parameter string into dictionary
    
    Args:
        param_string (str): Parameter string (e.g., "param1=value1&param2=value2")
        
    Returns:
        dict: Parsed parameters
    """
    if not param_string:
        return None
    
    params = {}
    try:
        pairs = param_string.split('&')
        for pair in pairs:
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key] = value
            else:
                params[pair] = ''
    except Exception:
        print(f"Error parsing parameters: {param_string}")
        return None
    
    return params


def main():
    """Main function"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Validate that at least one scanner is selected
    if not any([args.sqli, args.xss, args.lfi]):
        parser.error("At least one scanner must be specified (--sqli, --xss, or --lfi)")
    
    # Update configuration based on arguments
    config_updates = {
        'use_tor': args.tor,
        'delay_between_requests': args.delay,
        'timeout': args.timeout
    }
    
    if args.verbose:
        config_updates['log_level'] = 'DEBUG'
    elif args.quiet:
        config_updates['log_level'] = 'ERROR'
    
    update_config(**config_updates)
    
    # Initialize toolkit with threading and proxy settings
    toolkit = BugBountyToolkit(
        use_burp=args.burp,
        num_threads=args.threads
    )
    
    # Parse parameters
    parameters = parse_parameters(args.parameters)
    
    # Determine which scans to run
    scan_types = []
    if args.sqli:
        scan_types.append('sqli')
    if args.xss:
        scan_types.append('xss')
    if args.lfi:
        scan_types.append('lfi')
    
    # Display configuration
    if not args.quiet:
        print(f"Target URL: {args.url}")
        print(f"Scans to run: {', '.join(scan_types).upper()}")
        if args.threads > 1:
            print(f"Threads: {args.threads}")
        if args.tor:
            print("Using TOR proxy for anonymity")
        if args.burp:
            print("Routing traffic through Burp Suite (localhost:8080)")
        if parameters:
            print(f"Testing parameters: {list(parameters.keys())}")
        print("-" * 50)
    
    try:
        # Run selected scans
        results = toolkit.run_selected_scans(args.url, scan_types, parameters)
        
        # Print summary
        if not args.quiet:
            toolkit.print_summary(results)
        
        # Save results if requested
        if args.save:
            saved_file = toolkit.save_results_to_log(results)
            if saved_file and not args.quiet:
                print(f"\nResults saved to: {saved_file}")
        
        # Exit with appropriate code
        total_vulns = results.get('total_vulnerabilities', 0)
        
        if not args.quiet:
            if total_vulns > 0:
                print(f"\n🚨 Found {total_vulns} total vulnerabilities!")
            else:
                print(f"\n✅ No vulnerabilities found.")
        
        sys.exit(0 if total_vulns == 0 else 1)
    
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
