"""
Configuration file for BugBountyToolkit
Contains global settings and configuration options
"""

import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent

# Paths
PAYLOADS_DIR = BASE_DIR / "payloads"
LOGS_DIR = BASE_DIR / "logs"
UTILS_DIR = BASE_DIR / "utils"
SCANNER_DIR = BASE_DIR / "scanner"

# Ensure directories exist
LOGS_DIR.mkdir(exist_ok=True)

# Payload files
SQLI_PAYLOADS = PAYLOADS_DIR / "sqli.txt"
XSS_PAYLOADS = PAYLOADS_DIR / "xss.txt"
LFI_PAYLOADS = PAYLOADS_DIR / "lfi.txt"

# Default settings
DEFAULT_SETTINGS = {
    # HTTP settings
    'timeout': 10,
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'max_redirects': 5,
    'verify_ssl': False,
    
    # Rate limiting
    'delay_between_requests': 0.5,
    'max_concurrent_requests': 10,
    
    # Scanning settings
    'max_payload_length': 1000,
    'max_response_size': 1024 * 1024,  # 1MB
    'deep_scan': False,
    
    # Proxy settings
    'use_proxy': False,
    'proxy_rotation': True,
    'proxy_timeout': 10,
    
    # TOR settings
    'use_tor': False,
    'tor_port': 9050,
    'tor_control_port': 9051,
    'tor_password': None,
    
    # Logging settings
    'log_level': 'INFO',
    'log_to_file': True,
    'log_to_console': True,
    'max_log_size': 10 * 1024 * 1024,  # 10MB
    'log_backup_count': 5,
    
    # Output settings
    'output_format': 'json',  # json, xml, csv, txt
    'save_requests': False,
    'save_responses': False,
    'generate_report': True,
    
    # Vulnerability detection
    'confidence_threshold': 'medium',  # low, medium, high
    'false_positive_reduction': True,
    
    # SQL Injection settings
    'sqli_time_delay': 5,
    'sqli_error_detection': True,
    'sqli_blind_detection': True,
    'sqli_union_detection': True,
    
    # XSS settings
    'xss_test_forms': True,
    'xss_test_url_params': True,
    'xss_test_headers': False,
    'xss_payload_encoding': True,
    
    # LFI settings
    'lfi_test_common_files': True,
    'lfi_depth_levels': 5,
    'lfi_null_byte_injection': True,
    'lfi_encoding_bypass': True,
}

# Vulnerability severity mapping
SEVERITY_LEVELS = {
    'critical': ['sql injection', 'remote code execution', 'authentication bypass'],
    'high': ['xss', 'local file inclusion', 'path traversal', 'xxe'],
    'medium': ['information disclosure', 'cors misconfiguration'],
    'low': ['clickjacking', 'missing security headers'],
    'info': ['directory listing', 'debug information']
}

# Common HTTP headers for requests
DEFAULT_HEADERS = {
    'User-Agent': DEFAULT_SETTINGS['user_agent'],
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

# File extensions to test for LFI
LFI_FILE_EXTENSIONS = [
    '.txt', '.log', '.conf', '.config', '.ini', '.xml', '.json',
    '.php', '.asp', '.aspx', '.jsp', '.py', '.pl', '.rb',
    '.bak', '.backup', '.old', '.orig', '.save', '.tmp'
]

# Common parameter names that are often vulnerable
VULNERABLE_PARAMETERS = {
    'xss': [
        'q', 'search', 'query', 'keyword', 'term', 'name', 'username',
        'email', 'comment', 'message', 'content', 'text', 'data',
        'input', 'value', 'title', 'description', 'note', 'feedback'
    ],
    'sqli': [
        'id', 'user', 'username', 'userid', 'page', 'category', 'item',
        'product', 'article', 'news', 'post', 'topic', 'thread',
        'search', 'query', 'order', 'sort', 'filter', 'type'
    ],
    'lfi': [
        'file', 'page', 'include', 'path', 'document', 'folder',
        'dir', 'root', 'home', 'template', 'view', 'load',
        'read', 'open', 'get', 'fetch', 'import', 'require'
    ]
}

# Error patterns for different vulnerabilities
ERROR_PATTERNS = {
    'sqli': [
        r'mysql_fetch',
        r'ora-\d+',
        r'microsoft jet database',
        r'sqlite_master',
        r'postgresql.*error',
        r'warning:.*mysql',
        r'valid mysql result',
        r'mysqlclient',
        r'sql syntax.*error',
        r'unterminated quoted string',
        r'quoted string not properly terminated'
    ],
    'lfi': [
        r'root:x:0:0:',
        r'daemon:x:1:1:',
        r'\[boot loader\]',
        r'<\?xml version',
        r'<configuration>',
        r'DB_NAME.*DB_USER.*DB_PASSWORD'
    ],
    'xss': [
        r'<script.*?>.*?</script>',
        r'javascript:',
        r'onload\s*=',
        r'onerror\s*=',
        r'onmouseover\s*='
    ]
}

# Blacklist of domains/IPs to avoid testing
BLACKLISTED_DOMAINS = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '::1',
    'google.com',
    'facebook.com',
    'microsoft.com',
    'apple.com',
    'amazon.com'
]

# Custom configuration loader
class Config:
    """Configuration manager for BugBountyToolkit"""
    
    def __init__(self, config_file=None):
        """
        Initialize configuration
        
        Args:
            config_file (str): Path to custom configuration file
        """
        self.settings = DEFAULT_SETTINGS.copy()
        
        if config_file and os.path.exists(config_file):
            self.load_config_file(config_file)
        
        # Load environment variables
        self.load_env_vars()
    
    def load_config_file(self, config_file):
        """Load settings from configuration file"""
        try:
            import json
            with open(config_file, 'r') as f:
                custom_settings = json.load(f)
                self.settings.update(custom_settings)
        except Exception as e:
            print(f"Error loading config file: {e}")
    
    def load_env_vars(self):
        """Load settings from environment variables"""
        env_mapping = {
            'BBT_TIMEOUT': 'timeout',
            'BBT_USER_AGENT': 'user_agent',
            'BBT_USE_PROXY': 'use_proxy',
            'BBT_USE_TOR': 'use_tor',
            'BBT_LOG_LEVEL': 'log_level',
            'BBT_DELAY': 'delay_between_requests'
        }
        
        for env_var, setting_key in env_mapping.items():
            value = os.getenv(env_var)
            if value:
                # Convert string values to appropriate types
                if setting_key in ['timeout', 'delay_between_requests']:
                    try:
                        self.settings[setting_key] = float(value)
                    except ValueError:
                        pass
                elif setting_key in ['use_proxy', 'use_tor']:
                    self.settings[setting_key] = value.lower() in ['true', '1', 'yes']
                else:
                    self.settings[setting_key] = value
    
    def get(self, key, default=None):
        """Get configuration value"""
        return self.settings.get(key, default)
    
    def set(self, key, value):
        """Set configuration value"""
        self.settings[key] = value
    
    def get_headers(self):
        """Get HTTP headers with current user agent"""
        headers = DEFAULT_HEADERS.copy()
        headers['User-Agent'] = self.settings['user_agent']
        return headers
    
    def save_config(self, config_file):
        """Save current configuration to file"""
        try:
            import json
            with open(config_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False


# Global configuration instance
config = Config()

# Export commonly used values
TIMEOUT = config.get('timeout')
USER_AGENT = config.get('user_agent')
DELAY_BETWEEN_REQUESTS = config.get('delay_between_requests')
USE_PROXY = config.get('use_proxy')
USE_TOR = config.get('use_tor')
LOG_LEVEL = config.get('log_level')


def get_config():
    """Get global configuration instance"""
    return config


def update_config(**kwargs):
    """Update global configuration"""
    for key, value in kwargs.items():
        config.set(key, value)


def reset_config():
    """Reset configuration to defaults"""
    global config
    config = Config()
