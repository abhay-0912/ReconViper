"""
Proxy Manager Module
Provides functionality to manage HTTP/HTTPS proxies for web requests
"""

import requests
import random
import time
from itertools import cycle


class ProxyManager:
    """Proxy manager for rotating proxies during web requests"""
    
    def __init__(self, proxy_list=None, proxy_file=None, timeout=10):
        """
        Initialize proxy manager
        
        Args:
            proxy_list (list): List of proxy dictionaries
            proxy_file (str): Path to file containing proxy list
            timeout (int): Timeout for proxy testing
        """
        self.timeout = timeout
        self.working_proxies = []
        self.proxy_cycle = None
        
        # Load proxies from various sources
        if proxy_list:
            self.load_proxy_list(proxy_list)
        elif proxy_file:
            self.load_proxy_file(proxy_file)
        else:
            self.load_default_proxies()
        
        # Test and validate proxies
        self.test_all_proxies()
        
        # Setup proxy rotation
        if self.working_proxies:
            self.proxy_cycle = cycle(self.working_proxies)
    
    def load_proxy_list(self, proxy_list):
        """
        Load proxies from a list
        
        Args:
            proxy_list (list): List of proxy dictionaries or strings
        """
        self.proxies = []
        
        for proxy in proxy_list:
            if isinstance(proxy, dict):
                self.proxies.append(proxy)
            elif isinstance(proxy, str):
                # Parse string format: "http://ip:port" or "ip:port"
                parsed_proxy = self._parse_proxy_string(proxy)
                if parsed_proxy:
                    self.proxies.append(parsed_proxy)
    
    def load_proxy_file(self, proxy_file):
        """
        Load proxies from a file
        
        Args:
            proxy_file (str): Path to proxy file
        """
        self.proxies = []
        
        try:
            with open(proxy_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parsed_proxy = self._parse_proxy_string(line)
                        if parsed_proxy:
                            self.proxies.append(parsed_proxy)
        except FileNotFoundError:
            print(f"Proxy file {proxy_file} not found")
            self.load_default_proxies()
    
    def load_default_proxies(self):
        """Load default proxy list (empty by default)"""
        self.proxies = []
        print("No proxies configured. Operating without proxy rotation.")
    
    def _parse_proxy_string(self, proxy_string):
        """
        Parse proxy string into dictionary format
        
        Args:
            proxy_string (str): Proxy string (e.g., "http://ip:port" or "ip:port")
            
        Returns:
            dict: Proxy dictionary or None if invalid
        """
        try:
            if '://' in proxy_string:
                # Full URL format
                return {
                    'http': proxy_string,
                    'https': proxy_string
                }
            else:
                # IP:PORT format
                if ':' in proxy_string:
                    ip, port = proxy_string.split(':', 1)
                    proxy_url = f"http://{ip}:{port}"
                    return {
                        'http': proxy_url,
                        'https': proxy_url
                    }
        except Exception:
            pass
        
        return None
    
    def test_proxy(self, proxy):
        """
        Test if a proxy is working
        
        Args:
            proxy (dict): Proxy dictionary
            
        Returns:
            bool: True if proxy is working
        """
        test_urls = [
            'http://httpbin.org/ip',
            'http://icanhazip.com',
            'http://ipinfo.io/ip'
        ]
        
        for url in test_urls:
            try:
                response = requests.get(
                    url,
                    proxies=proxy,
                    timeout=self.timeout,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                
                if response.status_code == 200:
                    return True
            
            except Exception:
                continue
        
        return False
    
    def test_all_proxies(self):
        """Test all proxies and keep only working ones"""
        if not hasattr(self, 'proxies') or not self.proxies:
            return
        
        print(f"Testing {len(self.proxies)} proxies...")
        self.working_proxies = []
        
        for i, proxy in enumerate(self.proxies):
            print(f"Testing proxy {i+1}/{len(self.proxies)}: {proxy}")
            
            if self.test_proxy(proxy):
                self.working_proxies.append(proxy)
                print(f"✓ Proxy {i+1} is working")
            else:
                print(f"✗ Proxy {i+1} failed")
        
        print(f"Found {len(self.working_proxies)} working proxies out of {len(self.proxies)}")
    
    def get_proxy(self):
        """
        Get next proxy from rotation
        
        Returns:
            dict: Proxy dictionary or None if no proxies available
        """
        if self.proxy_cycle:
            return next(self.proxy_cycle)
        return None
    
    def get_random_proxy(self):
        """
        Get random proxy from working proxies
        
        Returns:
            dict: Random proxy dictionary or None if no proxies available
        """
        if self.working_proxies:
            return random.choice(self.working_proxies)
        return None
    
    def get_proxy_info(self, proxy):
        """
        Get information about current IP through proxy
        
        Args:
            proxy (dict): Proxy dictionary
            
        Returns:
            dict: IP information or None if failed
        """
        try:
            response = requests.get(
                'http://httpbin.org/ip',
                proxies=proxy,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
        
        except Exception as e:
            print(f"Error getting proxy info: {e}")
        
        return None
    
    def remove_proxy(self, proxy):
        """
        Remove a proxy from working proxies (if it stops working)
        
        Args:
            proxy (dict): Proxy to remove
        """
        if proxy in self.working_proxies:
            self.working_proxies.remove(proxy)
            print(f"Removed non-working proxy: {proxy}")
            
            # Recreate cycle with remaining proxies
            if self.working_proxies:
                self.proxy_cycle = cycle(self.working_proxies)
            else:
                self.proxy_cycle = None
    
    def make_request_with_retry(self, method, url, max_retries=3, **kwargs):
        """
        Make HTTP request with proxy retry logic
        
        Args:
            method (str): HTTP method
            url (str): Target URL
            max_retries (int): Maximum number of proxy retries
            **kwargs: Additional request arguments
            
        Returns:
            requests.Response: HTTP response or None if all proxies failed
        """
        last_exception = None
        
        for attempt in range(max_retries):
            proxy = self.get_proxy()
            
            if not proxy:
                # No proxy available, make direct request
                try:
                    return requests.request(method, url, timeout=self.timeout, **kwargs)
                except Exception as e:
                    last_exception = e
                    break
            
            try:
                response = requests.request(
                    method,
                    url,
                    proxies=proxy,
                    timeout=self.timeout,
                    **kwargs
                )
                return response
            
            except Exception as e:
                last_exception = e
                print(f"Request failed with proxy {proxy}: {str(e)}")
                
                # Test if proxy is still working
                if not self.test_proxy(proxy):
                    self.remove_proxy(proxy)
                
                # Add delay between retries
                time.sleep(1)
        
        print(f"All proxy attempts failed. Last error: {last_exception}")
        return None
    
    def get_stats(self):
        """
        Get proxy manager statistics
        
        Returns:
            dict: Statistics dictionary
        """
        total_proxies = len(self.proxies) if hasattr(self, 'proxies') else 0
        working_proxies = len(self.working_proxies)
        
        return {
            'total_proxies': total_proxies,
            'working_proxies': working_proxies,
            'success_rate': (working_proxies / total_proxies * 100) if total_proxies > 0 else 0,
            'has_proxy_rotation': bool(self.proxy_cycle)
        }


def main():
    """Test proxy manager functionality"""
    # Example proxy list (these are likely not working, just for demonstration)
    sample_proxies = [
        "8.8.8.8:3128",
        "1.1.1.1:8080",
        "http://proxy.example.com:8080"
    ]
    
    # Initialize proxy manager
    proxy_manager = ProxyManager(proxy_list=sample_proxies)
    
    # Get statistics
    stats = proxy_manager.get_stats()
    print(f"Proxy Statistics: {stats}")
    
    # Test making requests
    if proxy_manager.working_proxies:
        print("\nTesting request with proxy rotation...")
        for i in range(3):
            proxy = proxy_manager.get_proxy()
            print(f"Request {i+1} using proxy: {proxy}")
            
            # Get IP info through proxy
            ip_info = proxy_manager.get_proxy_info(proxy)
            if ip_info:
                print(f"Current IP: {ip_info.get('origin')}")
            
            time.sleep(1)
    else:
        print("No working proxies available")


if __name__ == "__main__":
    main()
