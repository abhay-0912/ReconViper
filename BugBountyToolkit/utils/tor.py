"""
TOR Proxy Module
Provides functionality to route traffic through TOR network for anonymity
"""

import requests
import socks
import socket
import time
from stem import Signal
from stem.control import Controller


class TorProxy:
    """TOR proxy manager for anonymous web requests"""
    
    def __init__(self, tor_port=9050, control_port=9051, password=None):
        """
        Initialize TOR proxy
        
        Args:
            tor_port (int): TOR SOCKS proxy port (default: 9050)
            control_port (int): TOR control port (default: 9051)
            password (str): TOR control password (if required)
        """
        self.tor_port = tor_port
        self.control_port = control_port
        self.password = password
        self.session = None
        self._setup_session()
    
    def _setup_session(self):
        """Setup requests session with TOR proxy"""
        self.session = requests.Session()
        
        # Configure proxy
        proxies = {
            'http': f'socks5://127.0.0.1:{self.tor_port}',
            'https': f'socks5://127.0.0.1:{self.tor_port}'
        }
        self.session.proxies.update(proxies)
        
        # Set headers to avoid detection
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.session.headers.update(headers)
    
    def is_tor_running(self):
        """
        Check if TOR is running and accessible
        
        Returns:
            bool: True if TOR is accessible
        """
        try:
            # Test connection to TOR proxy
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex(('127.0.0.1', self.tor_port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def get_current_ip(self):
        """
        Get current external IP address through TOR
        
        Returns:
            str: Current IP address or None if failed
        """
        try:
            response = self.session.get('http://httpbin.org/ip', timeout=10)
            return response.json().get('origin')
        except Exception as e:
            print(f"Error getting IP: {e}")
            return None
    
    def renew_connection(self):
        """
        Renew TOR connection to get new IP address
        
        Returns:
            bool: True if successful
        """
        try:
            with Controller.from_port(port=self.control_port) as controller:
                if self.password:
                    controller.authenticate(password=self.password)
                else:
                    controller.authenticate()
                
                controller.signal(Signal.NEWNYM)
                time.sleep(5)  # Wait for new circuit
                return True
        except Exception as e:
            print(f"Error renewing TOR connection: {e}")
            return False
    
    def make_request(self, method, url, **kwargs):
        """
        Make HTTP request through TOR
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            url (str): Target URL
            **kwargs: Additional arguments for requests
            
        Returns:
            requests.Response: HTTP response object
        """
        if not self.is_tor_running():
            raise Exception("TOR is not running or not accessible")
        
        try:
            if method.upper() == 'GET':
                return self.session.get(url, **kwargs)
            elif method.upper() == 'POST':
                return self.session.post(url, **kwargs)
            elif method.upper() == 'PUT':
                return self.session.put(url, **kwargs)
            elif method.upper() == 'DELETE':
                return self.session.delete(url, **kwargs)
            else:
                return self.session.request(method, url, **kwargs)
        except Exception as e:
            print(f"Error making request through TOR: {e}")
            raise
    
    def get(self, url, **kwargs):
        """Make GET request through TOR"""
        return self.make_request('GET', url, **kwargs)
    
    def post(self, url, **kwargs):
        """Make POST request through TOR"""
        return self.make_request('POST', url, **kwargs)
    
    def test_connection(self):
        """
        Test TOR connection and display information
        
        Returns:
            dict: Connection test results
        """
        results = {
            'tor_running': False,
            'current_ip': None,
            'connection_test': False
        }
        
        # Check if TOR is running
        results['tor_running'] = self.is_tor_running()
        
        if results['tor_running']:
            # Get current IP
            results['current_ip'] = self.get_current_ip()
            
            # Test connection
            try:
                response = self.get('http://httpbin.org/status/200', timeout=10)
                results['connection_test'] = response.status_code == 200
            except Exception:
                results['connection_test'] = False
        
        return results
    
    def close(self):
        """Close the session"""
        if self.session:
            self.session.close()


def main():
    """Test TOR proxy functionality"""
    tor = TorProxy()
    
    print("Testing TOR connection...")
    results = tor.test_connection()
    
    print(f"TOR Running: {results['tor_running']}")
    print(f"Current IP: {results['current_ip']}")
    print(f"Connection Test: {results['connection_test']}")
    
    if results['tor_running']:
        print("\nRenewing TOR connection...")
        if tor.renew_connection():
            new_ip = tor.get_current_ip()
            print(f"New IP: {new_ip}")
        else:
            print("Failed to renew connection")
    
    tor.close()


if __name__ == "__main__":
    main()
