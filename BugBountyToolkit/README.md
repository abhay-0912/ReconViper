# BugBountyToolkit

A comprehensive Python-based security testing toolkit designed for bug bounty hunters and penetration testers. This toolkit provides automated scanning capabilities for common web vulnerabilities including SQL Injection, Cross-Site Scripting (XSS), and Local File Inclusion (LFI).

## Features

### 🔍 Vulnerability Scanners
- **SQL Injection Scanner**: Detects SQL injection vulnerabilities using various techniques
  - Error-based detection
  - Union-based detection
  - Time-based blind detection
  - Boolean-based blind detection

- **XSS Scanner**: Comprehensive Cross-Site Scripting vulnerability detection
  - Reflected XSS detection
  - Form-based testing
  - Parameter-based testing
  - Encoding bypass techniques

- **LFI Checker**: Local File Inclusion vulnerability testing
  - Path traversal detection
  - Common file testing
  - Encoding bypass techniques
  - Null byte injection testing

### 🛠 Utility Modules
- **TOR Integration**: Route traffic through TOR network for anonymity
- **Proxy Management**: Support for HTTP/HTTPS proxy rotation
- **Advanced Logging**: Comprehensive logging with multiple output formats
- **Form Parser**: Automatic HTML form detection and parsing

### 📊 Reporting
- JSON output format
- Text-based reports
- Vulnerability confidence scoring
- Detailed scan summaries

## Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Required Dependencies
```bash
pip install requests beautifulsoup4 lxml
```

### Optional Dependencies (for TOR support)
```bash
pip install PySocks stem
```

### Clone the Repository
```bash
git clone https://github.com/abhay-0912/ReconViper.git
cd BugBountyToolkit
```

## Project Structure

```
BugBountyToolkit/
├── scanner/
│   ├── __init__.py
│   ├── sql_injector.py      # SQL injection scanner
│   ├── xss_scanner.py       # XSS vulnerability scanner
│   └── lfi_checker.py       # LFI vulnerability checker
├── payloads/
│   ├── sqli.txt            # SQL injection payloads
│   ├── xss.txt             # XSS payloads
│   └── lfi.txt             # LFI payloads
├── utils/
│   ├── __init__.py
│   ├── tor.py              # TOR proxy management
│   ├── logger.py           # Logging utilities
│   ├── form_parser.py      # HTML form parser
│   └── proxy.py            # HTTP proxy management
├── logs/                   # Log files directory
├── config.py              # Configuration settings
├── main.py               # Main application entry point
└── README.md            # This file
```

## Usage

### Basic Usage

Run all scans on a target:
```bash
python main.py -u http://example.com --all
```

Run specific vulnerability scans:
```bash
# SQL Injection only
python main.py -u http://example.com --sqli

# XSS only
python main.py -u http://example.com --xss

# LFI only
python main.py -u http://example.com --lfi

# Multiple specific scans
python main.py -u http://example.com --sqli --xss
```

### Advanced Usage

Test specific parameters:
```bash
python main.py -u http://example.com --all -p "id=1&search=test&page=admin"
```

Use proxy rotation:
```bash
python main.py -u http://example.com --all --proxy
```

Use TOR for anonymity:
```bash
python main.py -u http://example.com --all --tor
```

Save results to file:
```bash
python main.py -u http://example.com --all -o results.json -f json
```

Verbose output:
```bash
python main.py -u http://example.com --all -v
```

Custom timing settings:
```bash
python main.py -u http://example.com --all --delay 1.0 --timeout 15
```

### Command Line Options

```
Required Arguments:
  -u, --url URL         Target URL to scan

Scan Types:
  --all                 Run all available scans
  --sqli                Run SQL injection scan
  --xss                 Run XSS scan
  --lfi                 Run LFI scan

Parameters:
  -p, --parameters      Parameters to test (format: "param1=value1&param2=value2")

Output Options:
  -o, --output          Output file path
  -f, --format          Output format (json, txt)

Configuration:
  --proxy               Use proxy rotation
  --tor                 Use TOR for anonymity
  --delay               Delay between requests in seconds (default: 0.5)
  --timeout             Request timeout in seconds (default: 10)

Verbosity:
  -v, --verbose         Enable verbose output
  -q, --quiet           Quiet mode (minimal output)
```

## Configuration

The toolkit can be configured through the `config.py` file or environment variables:

### Environment Variables
- `BBT_TIMEOUT`: Request timeout in seconds
- `BBT_USER_AGENT`: Custom User-Agent string
- `BBT_USE_PROXY`: Enable proxy usage (true/false)
- `BBT_USE_TOR`: Enable TOR usage (true/false)
- `BBT_LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `BBT_DELAY`: Delay between requests

### Custom Configuration File
Create a JSON configuration file:
```json
{
  "timeout": 15,
  "user_agent": "Custom User Agent",
  "use_proxy": true,
  "delay_between_requests": 1.0,
  "log_level": "DEBUG"
}
```

## Payloads

The toolkit includes comprehensive payload lists for each vulnerability type:

### SQL Injection Payloads (`payloads/sqli.txt`)
- Error-based payloads
- Union-based payloads
- Time-based payloads
- Boolean-based payloads
- Advanced bypass techniques

### XSS Payloads (`payloads/xss.txt`)
- Basic script payloads
- Event handler payloads
- Encoded payloads
- Filter bypass payloads
- WAF bypass techniques

### LFI Payloads (`payloads/lfi.txt`)
- Path traversal payloads
- Null byte injection
- Encoding bypass techniques
- Windows and Unix specific paths

## Logging

The toolkit provides comprehensive logging capabilities:

- **Console Output**: Real-time scan progress
- **File Logging**: Detailed logs saved to `logs/` directory
- **Vulnerability Reports**: Structured vulnerability reports
- **Request/Response Logging**: Optional HTTP request/response logging

Log files are automatically rotated when they reach 10MB.

## Safety and Legal Considerations

⚠️ **IMPORTANT DISCLAIMER**: This toolkit is intended for authorized security testing only.

### Legal Requirements
- Only use this tool on systems you own or have explicit written permission to test
- Ensure you have proper authorization before conducting any security assessments
- Be aware of and comply with all applicable laws and regulations in your jurisdiction

### Ethical Usage
- Do not use this tool for malicious purposes
- Respect rate limits and avoid causing denial of service
- Report vulnerabilities responsibly through proper disclosure channels
- Always obtain proper authorization before testing

### Best Practices
- Start with passive reconnaissance
- Use appropriate delays between requests
- Monitor your testing to avoid system impact
- Document your testing activities
- Follow responsible disclosure practices

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes with appropriate tests
4. Ensure code follows the existing style
5. Submit a pull request with a clear description

### Areas for Contribution
- Additional vulnerability scanners
- New payload categories
- Performance improvements
- Documentation enhancements
- Bug fixes and stability improvements

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Users are responsible for ensuring they have proper authorization before conducting any security testing.

## Changelog

### Version 1.0.0
- Initial release
- SQL injection scanner
- XSS scanner
- LFI checker
- TOR and proxy support
- Comprehensive logging
- JSON/text output formats

## Support

For support, questions, or feature requests:
- Create an issue on GitHub
- Check the documentation
- Review existing issues for similar problems

## Acknowledgments

- Thanks to the security research community for vulnerability research
- Payload lists compiled from various public sources
- Built with Python and open-source libraries
