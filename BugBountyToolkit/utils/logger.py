"""
Logger Module
Provides comprehensive logging functionality for the BugBountyToolkit
"""

import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler


class Logger:
    """Enhanced logger with multiple output options and formatting"""
    
    def __init__(self, name, log_level=logging.INFO, log_dir="logs"):
        """
        Initialize logger
        
        Args:
            name (str): Logger name (usually module name)
            log_level (int): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_dir (str): Directory to store log files
        """
        self.name = name
        self.log_dir = log_dir
        self.logger = self._setup_logger(log_level)
    
    def _setup_logger(self, log_level):
        """Setup logger with file and console handlers"""
        # Create logger
        logger = logging.getLogger(self.name)
        logger.setLevel(log_level)
        
        # Avoid duplicate handlers
        if logger.handlers:
            return logger
        
        # Create logs directory if it doesn't exist
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        simple_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        
        # File handler with rotation
        log_file = os.path.join(self.log_dir, f"{self.name}.log")
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(simple_formatter)
        
        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def debug(self, message):
        """Log debug message"""
        self.logger.debug(message)
    
    def info(self, message):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message):
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message):
        """Log critical message"""
        self.logger.critical(message)
    
    def log_vulnerability(self, vulnerability):
        """
        Log vulnerability finding with structured format
        
        Args:
            vulnerability (dict): Vulnerability information
        """
        vuln_msg = f"VULNERABILITY FOUND - Type: {vulnerability.get('type', 'Unknown')}"
        
        if 'parameter' in vulnerability:
            vuln_msg += f" | Parameter: {vulnerability['parameter']}"
        
        if 'url' in vulnerability:
            vuln_msg += f" | URL: {vulnerability['url']}"
        
        if 'payload' in vulnerability:
            vuln_msg += f" | Payload: {vulnerability['payload'][:100]}..."
        
        if 'confidence' in vulnerability:
            vuln_msg += f" | Confidence: {vulnerability['confidence']}"
        
        self.logger.warning(vuln_msg)
    
    def log_scan_start(self, scan_type, target):
        """
        Log scan start
        
        Args:
            scan_type (str): Type of scan
            target (str): Target URL or identifier
        """
        self.logger.info(f"Starting {scan_type} scan on target: {target}")
    
    def log_scan_complete(self, scan_type, target, vulnerabilities_found):
        """
        Log scan completion
        
        Args:
            scan_type (str): Type of scan
            target (str): Target URL or identifier
            vulnerabilities_found (int): Number of vulnerabilities found
        """
        self.logger.info(f"Completed {scan_type} scan on {target}. Found {vulnerabilities_found} vulnerabilities")
    
    def log_request(self, method, url, status_code, response_time=None):
        """
        Log HTTP request
        
        Args:
            method (str): HTTP method
            url (str): Request URL
            status_code (int): HTTP status code
            response_time (float): Response time in seconds
        """
        msg = f"HTTP {method} {url} - Status: {status_code}"
        if response_time:
            msg += f" - Time: {response_time:.2f}s"
        
        if status_code >= 400:
            self.logger.warning(msg)
        else:
            self.logger.debug(msg)
    
    def log_error_with_details(self, error_msg, exception=None, context=None):
        """
        Log error with additional context
        
        Args:
            error_msg (str): Error message
            exception (Exception): Exception object (if available)
            context (dict): Additional context information
        """
        full_msg = f"ERROR: {error_msg}"
        
        if exception:
            full_msg += f" | Exception: {str(exception)}"
        
        if context:
            context_str = " | ".join([f"{k}: {v}" for k, v in context.items()])
            full_msg += f" | Context: {context_str}"
        
        self.logger.error(full_msg)
    
    def create_report_file(self, scan_results, scan_type):
        """
        Create a detailed report file for scan results
        
        Args:
            scan_results (list): List of vulnerability dictionaries
            scan_type (str): Type of scan performed
            
        Returns:
            str: Path to generated report file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.log_dir, f"{scan_type}_report_{timestamp}.txt")
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"BugBountyToolkit - {scan_type.upper()} Scan Report\n")
                f.write("=" * 50 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Vulnerabilities Found: {len(scan_results)}\n\n")
                
                for i, vuln in enumerate(scan_results, 1):
                    f.write(f"Vulnerability #{i}\n")
                    f.write("-" * 20 + "\n")
                    
                    for key, value in vuln.items():
                        f.write(f"{key.title()}: {value}\n")
                    
                    f.write("\n")
            
            self.logger.info(f"Report generated: {report_file}")
            return report_file
            
        except Exception as e:
            self.logger.error(f"Failed to create report file: {str(e)}")
            return None
    
    def set_level(self, level):
        """
        Change logging level
        
        Args:
            level (int): New logging level
        """
        self.logger.setLevel(level)
        for handler in self.logger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, RotatingFileHandler):
                handler.setLevel(level)


def main():
    """Test logger functionality"""
    logger = Logger("test_logger")
    
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")
    
    # Test vulnerability logging
    test_vuln = {
        'type': 'XSS',
        'parameter': 'search',
        'url': 'http://example.com/search?q=test',
        'payload': '<script>alert("XSS")</script>',
        'confidence': 'High'
    }
    logger.log_vulnerability(test_vuln)
    
    # Test scan logging
    logger.log_scan_start("XSS", "http://example.com")
    logger.log_scan_complete("XSS", "http://example.com", 1)


if __name__ == "__main__":
    main()
