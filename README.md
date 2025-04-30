# IDOR and Broken Authentication Vulnerability Tester

**IDORipper** helps detect Insecure Direct Object References (IDOR) and broken authentication vulnerabilities by crawling a target website, sending requests with different authorization headers (original and altered), and comparing the responses. 

---

## Features

- Crawls websites using Playwright.
- Extracts all HTTP methods, including GET, POST, and others.
- Detects potential IDOR vulnerabilities.
- Identifies broken authentication issues.
- Supports header manipulation to simulate different users.

---

## Requirements

- Python 3.x
- `requests` library
- `beautifulsoup4` library
- `playwright` library

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/alvinsenjaya/IDORipper
   cd IDORipper
   ```
2. Install the required dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```
3. Ensure Playwright is installed and set up:
   ```bash
   playwright install
   ```


---

## Usage

### Basic Command

To start the Advanced Web and API Tester with a target URL and a header:

```bash
python IDORipper.py -u <target_url> -H "<Header1>:<Value1>" -H "<Header2>:<Value2>"
```

### Single Header

If you want to specify a single header:

```bash
python IDORipper.py -u https://example.com -H "User-Agent: MyCustomAgent"
```

### Multiple Headers

For specifying multiple headers:

```bash
python IDORipper.py -u https://example.com -H "User-Agent: MyCustomAgent" -H "Authorization: Bearer <token>"
```

### Single Altered Header

To add altered headers for testing:

```bash
python IDORipper.py -u https://example.com -H "User-Agent: MyCustomAgent" -A "User-Agent: AlteredAgent"
```

### Multiple Altered Headers

For multiple altered headers:

```bash
python IDORipper.py -u https://example.com -H "User-Agent: MyCustomAgent" -H "Authorization: Bearer <token>" -A "User-Agent: AlteredAgent" -A "Authorization: AlteredToken"
```

### Single Domain

To limit crawling to a single domain:

```bash
python IDORipper.py -u https://example.com -H "User-Agent: MyCustomAgent" --domain example.com
```

### Multiple Domains

To limit crawling to multiple domains:

```bash
python IDORipper.py -u https://example.com -H "User-Agent: MyCustomAgent" --domain example.com anotherdomain.com
```

### Parameters for Placeholder Replacement

You can specify parameters for placeholder replacement in the URL or request body:

```bash
python IDORipper.py -u https://example.com -H "User-Agent: MyCustomAgent" --parameter "user=alice;token=12345"
```

### Exclude URLs

To exclude specific URLs from crawling:

```bash
python IDORipper.py -u https://example.com -H "User-Agent: MyCustomAgent" --exclude "/login" "/signup"
```

### Exclude Responses Containing Certain Body Content

To exclude responses containing specific body content (e.g., strings in the response body):

```bash
python IDORipper.py -u https://example.com -H "User-Agent: MyCustomAgent" --exclude-result-with-body "Access Denied" "Forbidden"
```

This option will exclude requests from testing if the response body contains the specified strings.

### Depth of Crawling

To set the maximum crawl depth:

```bash
python IDORipper.py -u https://example.com -H "User-Agent: MyCustomAgent" --depth 3
```

### All Parameters

To use all parameters for replacing placeholders and testing:

```bash
python IDORipper.py -u https://example.com -H "User-Agent: MyCustomAgent" --parameter "user=alice;token=12345" --domain example.com --depth 3 --exclude "/login" --exclude-result-with-body "Access Denied"
```

---

## Contributing

Contributions are welcome! Feel free to fork the repository and submit a pull request.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

