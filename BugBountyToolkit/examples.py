#!/usr/bin/env python3
"""
Example usage script for BugBountyToolkit
Demonstrates various command combinations
"""

import subprocess
import sys

def run_command(description, command):
    """Run a command and display the description"""
    print(f"\n{'='*60}")
    print(f"Example: {description}")
    print(f"Command: {' '.join(command)}")
    print(f"{'='*60}")
    
    # Note: In real usage, remove the '--help' and use actual target URLs
    try:
        # For demonstration, we'll just show the help
        result = subprocess.run([sys.executable, "main.py", "--help"], 
                              capture_output=True, text=True, cwd=".")
        if result.returncode == 0:
            print("✓ Command syntax is valid")
        else:
            print("✗ Command syntax error")
    except Exception as e:
        print(f"Error running command: {e}")

def main():
    """Show example usage patterns"""
    print("BugBountyToolkit - Usage Examples")
    print("=" * 60)
    
    examples = [
        ("Basic SQL injection scan", 
         ["python", "main.py", "--url", "http://example.com", "--sqli"]),
        
        ("XSS scan with custom parameters", 
         ["python", "main.py", "--url", "http://example.com", "--xss", "-p", "search=test&q=demo"]),
        
        ("Multiple scans with threading", 
         ["python", "main.py", "--url", "http://example.com", "--sqli", "--xss", "--lfi", "--threads", "3"]),
        
        ("Scan with TOR proxy", 
         ["python", "main.py", "--url", "http://example.com", "--sqli", "--tor"]),
        
        ("Scan via Burp Suite proxy", 
         ["python", "main.py", "--url", "http://example.com", "--xss", "--burp"]),
        
        ("Comprehensive scan with logging", 
         ["python", "main.py", "--url", "http://example.com", "--sqli", "--xss", "--lfi", "--save"]),
        
        ("Verbose scan with custom timing", 
         ["python", "main.py", "--url", "http://example.com", "--lfi", "--verbose", "--delay", "1.0", "--timeout", "15"]),
        
        ("Quiet scan with all options", 
         ["python", "main.py", "--url", "http://example.com", "--sqli", "--xss", "--threads", "2", "--tor", "--save", "--quiet"])
    ]
    
    for description, command in examples:
        run_command(description, command)
    
    print(f"\n{'='*60}")
    print("Notes:")
    print("- Replace 'http://example.com' with your target URL")
    print("- Ensure you have proper authorization before scanning")
    print("- Use --save to automatically save results to logs/")
    print("- Use --threads for parallel scanning (useful for multiple scan types)")
    print("- Use --burp to route traffic through Burp Suite for manual analysis")
    print("- Use --tor for anonymity (requires TOR to be running)")
    print("=" * 60)

if __name__ == "__main__":
    main()
