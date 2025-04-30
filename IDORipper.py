import argparse
import requests
from bs4 import BeautifulSoup
import hashlib
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse, parse_qsl
from playwright.sync_api import sync_playwright
import json
import yaml
import xml.etree.ElementTree as ET
import base64
import Levenshtein

def calculate_similarity(text1, text2):
    """Calculate the similarity between two texts and return the percentage."""
    if not text1 or not text2:
        return 0.0  # No similarity if either text is empty

    # Calculate Levenshtein distance
    distance = Levenshtein.distance(text1, text2)
    max_len = max(len(text1), len(text2))

    # Similarity is calculated as (1 - normalized distance)
    similarity = (1 - (distance / max_len)) * 100
    return similarity

def print_banner():
    banner = r"""
     ________  ________  ________  ________  ___  ________  ________  _______   ________     
    |\  \|\   ___ \|\   __  \|\   __  \|\  \|\   __  \|\   __  \|\  ___ \ |\   __  \    
    \ \  \ \  \_|\ \ \  \|\  \ \  \|\  \ \  \ \  \|\  \ \  \|\  \ \   __/|\ \  \|\  \   
     \ \  \ \  \ \\ \ \  \\\  \ \   _  _\ \  \ \   ____\ \   ____\ \  \_|/_\ \   _  _\  
      \ \  \ \  \_\\ \ \  \\\  \ \  \\  \\ \  \ \  \___|\ \  \___|\ \  \_|\ \ \  \\  \| 
       \ \__\ \_______\ \_______\ \__\\ _\\ \__\ \__\    \ \__\    \ \_______\ \__\\ _\ 
        \|__|\|_______|\|_______|\|__|\|__|\|__|\|__|     \|__|     \|_______|\|__|\|__|
                                                                                    
    **************************************   
     *       IDORipper Tool              *
     *       Created by Alvin Senjaya    *
    **************************************

    """
    print(banner)

def parse_headers_from_burp(headers_text, base64_flag=False):
    """
    Parses a raw HTTP header string into a dictionary. If base64 encoding is not present, formats headers properly.
    
    Args:
        headers_text (str): The raw HTTP headers as a string.
        base64_flag (bool): Whether the request is base64 encoded or not.
    
    Returns:
        dict: A dictionary with header keys and values.
    """
    headers = {}
    if not base64_flag:
        # If not base64, split the headers based on newline characters and format properly
        for line in headers_text.split('\n'):
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key.lower()] = value.strip()  # Store headers with lowercase keys for consistency
    else:
        # For base64 encoded request, follow existing method
        for line in headers_text.split('\r\n'):
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key.lower()] = value.strip()  # Store headers with lowercase keys for consistency
    return headers

def extract_requests_from_burp(file_path, domains=None, exclude_urls=None):
    """
    Extracts HTTP requests from a Burp Suite traffic file (XML format).
    
    Args:
        file_path (str): Path to the Burp Suite traffic file (XML).
        domains (list): List of domains to filter requests. If None, no filtering is applied.
        exclude_urls (list): List of substrings to exclude from URLs. If None, no exclusion is applied.

    Returns:
        list: A list of detected requests as dictionaries containing method, url, headers, and body.
    """
    try:
        # Parse the XML file
        tree = ET.parse(file_path)
        root = tree.getroot()

        detected_requests = []
        seen_requests = set()  # To store unique requests (to avoid duplicates)

        # Iterate through each 'item' in the XML file
        for item in root.findall('item'):
            # Extract method, URL, and request elements
            method_element = item.find('method')
            url_element = item.find('url')
            request_base64_element = item.find('request')

            # Validate and handle missing or empty fields with fallbacks
            method = method_element.text.strip() if method_element is not None and method_element.text else 'UNKNOWN_METHOD'
            url = url_element.text.strip() if url_element is not None and url_element.text else 'UNKNOWN_URL'
            request_base64 = request_base64_element.text.strip() if request_base64_element is not None and request_base64_element.text else ''
            base64_flag = request_base64_element.get('base64') == 'true' if request_base64_element is not None else False

            # Decode the base64 encoded request if applicable
            if base64_flag:
                try:
                    decoded_request = base64.b64decode(request_base64).decode('utf-8', 'ignore')
                except Exception as e:
                    print(f"Error decoding base64 request: {e}")
                    decoded_request = request_base64
            else:
                decoded_request = request_base64

            # Split the decoded request into headers and body (separated by two newlines)
            try:
                headers_text, body = decoded_request.split('\r\n\r\n', 1)
            except ValueError:
                # Handle case where the body is empty or improperly formatted
                headers_text, body = decoded_request, ''

            # Parse headers into a dictionary
            headers = parse_headers_from_burp(headers_text, base64_flag)

            # If domains are provided, filter requests based on domain match
            if domains:
                parsed_url = urlparse(url)
                if not any(domain in parsed_url.netloc for domain in domains):
                    continue  # Skip requests that don't match the specified domains

            # If exclude_urls is provided, skip requests that contain any of the excluded substrings in the URL
            if exclude_urls:
                if any(exclude_url in url for exclude_url in exclude_urls):
                    continue  # Skip requests that contain any of the excluded substrings

            # Avoid duplicate requests (based on URL and method)
            request_signature = (method, url)
            if request_signature not in seen_requests:
                seen_requests.add(request_signature)
                detected_requests.append({
                    "method": method,
                    "url": url,
                    "headers": headers,  # Store headers as a dictionary
                    "body": body if body else None  # Set body to None if it is empty
                })

        return detected_requests

    except Exception as e:
        print(f"Error while processing Burp Suite file: {e}")
        raise  # Re-raise the error after logging it

def parse_headers(header_list):
    """
    Parse the list of headers into a dictionary.
    """
    headers = {}
    for header in header_list:
        try:
            key, value = header.split(":", 1)  # Split only on the first colon
            headers[key.strip()] = value.strip()
        except ValueError:
            print(f"🚨 ERROR: Invalid header format: {header}")
            continue
    return headers

def detect_http_methods(soup, current_url, page):
    """
    Detects HTTP methods used in forms on a given web page and returns details about them.

    Args:
        soup (BeautifulSoup): A BeautifulSoup object representing the parsed HTML content.
        current_url (str): The base URL of the page to resolve relative URLs.
        page (playwright.sync_api.Page): The Playwright page object to extract dynamic data.

    Returns:
        list: A list of dictionaries, each containing the HTTP method, action URL,
              headers, and data dictionary of input fields for each form found.
    """
    methods = []
    forms = soup.find_all('form')

    for form in forms:
        method = form.get('method', 'GET').upper()
        action = form.get('action', '')
        action_url = urljoin(current_url, action)
        inputs = form.find_all('input')
        data = {input.get('name'): input.get('value', '') for input in inputs}

        # Extract additional headers dynamically from the page
        request_headers = page.evaluate("""() => {
            return Object.fromEntries([...new Headers(document)]);
        }""")

        methods.append({
            "method": method,
            "url": action_url,
            "headers": request_headers,
            "body": data
        })

    return methods

def crawl_site_playwright(url, headers, domains, exclude, max_depth, verbose):
    """
    Crawl a site, detect links, forms, and capture all API requests, returning request details.

    Args:
        url (str): The starting URL for the crawl.
        headers (dict): HTTP headers for requests.
        domains (list): Allowed domains for the crawl.
        exclude (list): Excluded URL patterns.
        max_depth (int): Maximum crawl depth.
        verbose (bool): Enable verbose logging.

    Returns:
        list: A list of unique captured requests with URLs, HTTP methods, headers, and payloads.
    """
    visited = set()
    to_visit = [(url, 0)]
    detected_requests = []  # Store details of requests made by the page

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context()
        context.set_extra_http_headers(headers)

        with context.new_page() as page:
            # Capture all network requests
            def capture_request(request):
                if not any(excl in request.url for excl in exclude) and (
                    not domains or any(domain in urlparse(request.url).netloc for domain in domains)
                ):
                    detected_requests.append({
                        "method": request.method,
                        "url": request.url,
                        "headers": request.headers,
                        "body": request.post_data or ""  # Capture payload for POST/PUT requests
                    })

            # Attach request listener
            page.on("request", capture_request)

            while to_visit:
                current_url, depth = to_visit.pop()

                # Skip processing if max depth exceeded, URL already visited, or excluded
                if depth > max_depth or current_url in visited or any(excl in current_url for excl in exclude):
                    continue

                if verbose:
                    print(f"Visiting: {current_url} (Depth: {depth})")
                visited.add(current_url)

                try:
                    # Use `networkidle` and an appropriate timeout for page navigation
                    page.goto(current_url, wait_until="networkidle", timeout=15000)  # 15 seconds for network idle

                    try:
                        # Wait for the body element to be visible
                        page.wait_for_selector("body", timeout=10000)  # 10 seconds for visibility
                    except Exception:
                        # Fallback to checking if the body is attached to the DOM
                        page.wait_for_selector("body", state="attached", timeout=10000)

                    # Once the body is available, proceed with scraping
                    soup = BeautifulSoup(page.content(), 'html.parser')

                    # Find and process links
                    links = [urljoin(current_url, a['href']) for a in soup.find_all('a', href=True)]
                    filtered_links = [
                        link for link in links
                        if not any(excl in link for excl in exclude)
                        and (not domains or any(domain in urlparse(link).netloc for domain in domains))
                    ]
                    to_visit.extend((link, depth + 1) for link in filtered_links)

                    # Detect forms and add them to detected_requests
                    methods = detect_http_methods(soup, current_url, page)
                    detected_requests.extend(methods)

                except Exception as e:
                    if verbose:
                        print(f"Error visiting {current_url}: {e}")

        browser.close()

    # Combine unique requests by both URL and HTTP method
    unique_requests = {req['url'] + req['method']: req for req in detected_requests}.values()

    return list(unique_requests)

# Note: The detect_http_methods function is assumed to be implemented elsewhere in your code.

def load_openapi_spec(file_path):
    """
    Loads an OpenAPI specification from a file, parsing it as either JSON or YAML.

    Args:
        file_path (str): The path to the file containing the OpenAPI specification.

    Returns:
        dict: A dictionary representing the parsed OpenAPI specification.

    Raises:
        ValueError: If the file content cannot be parsed as JSON or YAML.
    """
    # Read the content of the file
    with open(file_path, 'r') as file:
        content = file.read()

    # Attempt to parse the content as JSON
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # If JSON parsing fails, attempt to parse the content as YAML
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            # Raise an error if the content cannot be parsed as either format
            raise ValueError(f"Failed to parse OpenAPI spec from {file_path}: {e}")


def extract_api_targets(openapi_spec, parameters=None, exclude_urls=None):
    """
    Extracts API target details from an OpenAPI specification.

    Args:
        openapi_spec (dict): The parsed OpenAPI specification as a dictionary.
        parameters (dict, optional): A dictionary of parameters to replace placeholders in the API paths and request bodies.
        exclude_urls (list, optional): A list of substrings to exclude from the URLs.

    Returns:
        list: A list of dictionaries where each dictionary contains the HTTP method, the full URL, request headers, and the request body for each API path.
    """
    # List to hold API target details (method, URL, headers, and body)
    detected_requests = []

    # Extract the base URL from the 'servers' section of the OpenAPI spec
    base_url = openapi_spec.get('servers', [{}])[0].get('url', '')

    # Iterate through each path and its associated methods in the OpenAPI spec
    for path, methods in openapi_spec.get('paths', {}).items():
        for method, details in methods.items():
            # Convert method to uppercase to standardize it
            method = method.upper()
            # Construct the full URL by joining the base URL and the path
            url = urljoin(base_url, path)
            body = None  # Initialize the request body as None

            # Initialize headers as an empty dictionary
            headers = {}

            # Extract headers from the 'parameters' section if they are in the 'header' location
            for param in details.get('parameters', []):
                if param.get('in') == 'header':
                    headers[param['name']] = parameters.get(param['name'], f"{{{param['name']}}}" if parameters else f"{{{param['name']}}}")

            # Check if the 'requestBody' key exists in the method details
            if 'requestBody' in details:
                content = details['requestBody'].get('content', {})
                # Check if 'application/json' is present in the content types
                if 'application/json' in content:
                    schema = content['application/json'].get('schema', {})
                    body = {}
                    # Populate the body dictionary with the schema properties
                    for key, value in schema.get('properties', {}).items():
                        # Use the provided parameter value if available; otherwise, use the schema's example or a placeholder
                        if parameters and key in parameters:
                            body[key] = parameters[key]
                        else:
                            body[key] = value.get('example', f"{{{key}}}")

            # Extract query parameters and replace placeholders if necessary
            params = {
                param['name']: (parameters[param['name']] if parameters and param['name'] in parameters else f"{{{param['name']}}}")
                for param in details.get('parameters', []) if param['in'] == 'query'
            }
            # Append query parameters to the URL if any exist
            if params:
                url += "?" + "&".join(f"{k}={v}" for k, v in params.items())

            # If exclude_urls is provided, skip requests that contain any of the excluded substrings in the URL
            if exclude_urls:
                if any(exclude_url in url for exclude_url in exclude_urls):
                    continue  # Skip requests that contain any of the excluded substrings

            # Append the method, full URL, headers, and body to the detected_requests list
            detected_requests.append({
                "method": method,
                "url": url,
                "headers": headers,  # Now including the headers extracted from the OpenAPI spec
                "body": body or ""
            })

    return detected_requests


def replace_parameters(all_requests, parameters, verbose=False):
    """
    Replace parameter values in all_requests with values supplied via the parameters dictionary.
    This function replaces query parameters in the URL and form-encoded data in the request body.

    Args:
        all_requests (list): List of dictionaries containing HTTP method, URL, request body (data), and optional headers.
        parameters (dict): Dictionary of parameter values for direct replacement.
        verbose (bool): Enable verbose output for debugging.

    Returns:
        list: A list of updated requests with parameter values replaced.
    """
    updated_requests = []  # List to store requests with replaced parameters

    # Iterate over each request in the input list
    for request in all_requests:
        method = request.get("method")
        url = request.get("url")
        data = request.get("body", "")
        headers = request.get("headers", {})

        # Parse the URL to separate the path and query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Replace query parameter values if they match keys in the parameters dictionary
        updated_query_params = {}
        for key, values in query_params.items():
            if key in parameters:
                updated_value = parameters[key]
                print(f"Replacing value of query parameter '{key}' with '{updated_value}'")
                updated_query_params[key] = [updated_value]  # Replace with new value
            else:
                updated_query_params[key] = values  # Keep original if not in parameters

        # Reconstruct the URL with updated query parameters
        updated_query_string = urlencode(updated_query_params, doseq=True)
        updated_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            updated_query_string,
            parsed_url.fragment
        ))

        # Replace values in the request body if it's form data (application/x-www-form-urlencoded)
        if isinstance(data, str):
            form_data = parse_qsl(data)
            updated_form_data = []
            for key, value in form_data:
                if key in parameters:
                    updated_value = parameters[key]
                    print(f"Replacing value '{key}' in form data with '{updated_value}'")
                    updated_form_data.append((key, updated_value))
                else:
                    updated_form_data.append((key, value))
            data = urlencode(updated_form_data)

        # Replace values in JSON bodies if the data is a dictionary
        if isinstance(data, dict):
            updated_data = {}
            for key, val in data.items():
                if key in parameters:
                    updated_val = parameters[key]
                    print(f"Replacing value '{key}' in data key '{key}' with '{updated_val}'")
                    updated_data[key] = updated_val
                else:
                    updated_data[key] = val  # Keep values unchanged if not in parameters
            data = updated_data

        # Replace values in headers if they are present and are a dictionary
        if headers and isinstance(headers, dict):
            updated_headers = {}
            for key, val in headers.items():
                if key in parameters:
                    updated_val = parameters[key]
                    print(f"Replacing value '{key}' in header '{key}' with '{updated_val}'")
                    updated_headers[key] = updated_val
                else:
                    updated_headers[key] = val  # Keep header values unchanged if not in parameters
            headers = updated_headers

        # Append the updated request to the result in the required format
        updated_requests.append({
            "method": method,
            "url": updated_url,
            "headers": headers,  # Now including headers
            "body": data or ""    # Make sure to provide the body as empty string if None
        })

    return updated_requests  # Return the list of updated requests


def replace_placeholders(all_requests, parameters, verbose=False):
    """
    Replace placeholders in all_requests with values supplied via the parameters dictionary.

    Args:
        all_requests (list): List of dictionaries containing HTTP method, URL, request body (body), and optional headers.
        parameters (dict): Dictionary of parameter values for placeholder replacement.
        verbose (bool): Enable verbose output for debugging.

    Returns:
        list: A list of updated requests with placeholders replaced by parameter values.
    """
    updated_requests = []  # List to store requests with replaced placeholders

    # Iterate over each request in the input list
    for request in all_requests:
        method = request.get("method")
        url = request.get("url")
        body = request.get("body")
        headers = request.get("headers", {})

        # Replace placeholders in the URL
        for param, value in parameters.items():
            placeholder = f"{{{param}}}"
            if placeholder in url:
                print(f"Replacing placeholder {placeholder} in URL with value '{value}'")
                url = url.replace(placeholder, value)

        # Replace placeholders in the request body if it's a dictionary
        if body and isinstance(body, dict):
            updated_body = {}
            for key, val in body.items():
                if isinstance(val, str):  # Only replace placeholders in string values
                    for param, value in parameters.items():
                        placeholder = f"{{{param}}}"
                        if placeholder in val:
                            updated_val = val.replace(placeholder, value)
                            print(f"Replacing placeholder {placeholder} in body key '{key}' with value '{updated_val}'")
                            updated_body[key] = updated_val
                        else:
                            updated_body[key] = val
                else:
                    updated_body[key] = val  # Keep non-string values unchanged
            body = updated_body

        # Replace placeholders in headers if they are present and are a dictionary
        updated_headers = {}
        if headers and isinstance(headers, dict):
            for key, val in headers.items():
                if isinstance(val, str):  # Replace only in string values
                    for param, value in parameters.items():
                        placeholder = f"{{{param}}}"
                        if placeholder in val:
                            updated_val = val.replace(placeholder, value)
                            print(f"Replacing placeholder {placeholder} in header '{key}' with value '{updated_val}'")
                            updated_headers[key] = updated_val
                        else:
                            updated_headers[key] = val
                else:
                    updated_headers[key] = val  # Keep non-string header values unchanged
            headers = updated_headers

        # Append the updated request to the result, including headers and body
        updated_requests.append({
            "method": method,
            "url": url,
            "headers": headers,  # Including the headers as extracted
            "body": body or ""  # If body is None, replace it with an empty string
        })

    return updated_requests  # Return the list of updated requests

def replace_headers(headers, modified_header):
    """Replace a header in the request with the modified header."""
    updated_headers = headers.copy()
    
    for key, value in modified_header.items():
        # Make header names case-insensitive
        header_key = next((k for k in updated_headers if k.lower() == key.lower()), None)
        
        if header_key:
            updated_headers[header_key] = value
        else:
            updated_headers[key] = value  # Add new header if not found
    
    return updated_headers

def add_or_replace_headers(original_headers, supplied_headers):
    """Add missing headers from supplied_headers to original_headers, replace if present (case-insensitive)."""
    updated_headers = original_headers.copy()
    
    # Create a lowercase version of the original headers for case-insensitive comparison
    lower_original_headers = {key.lower(): key for key in updated_headers}
    
    for key, value in supplied_headers.items():
        # Compare in a case-insensitive manner
        if key.lower() in lower_original_headers:
            # Replace the existing header
            updated_headers[lower_original_headers[key.lower()]] = value
        else:
            # Add the new header
            updated_headers[key] = value
    
    return updated_headers

def remove_specified_auth_headers(headers, auth_headers):
    """Remove authentication-related headers from the request headers."""
    stripped_headers = headers.copy()

    for key in auth_headers:
        # Make header names case-insensitive
        header_key = next((k for k in stripped_headers if k.lower() == key.lower()), None)
        
        if header_key:
            del stripped_headers[header_key]
    
    return stripped_headers

def send_request(method, url, headers, data=None, verbose=False):
    """Send an HTTP request and return the response."""
    try:
        if data is None:  # Skip sending the body if data is not provided
            response = requests.request(method, url, headers=headers)
        else:
            response = requests.request(method, url, headers=headers, json=data)

        response.raise_for_status()  # Will throw an exception for status codes 4xx/5xx

        return response
    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"Request failed for {method.upper()} {url} with error: {e}\n")
        return None
    except Exception as e:
        if verbose:
            print(f"Unexpected error occurred while sending {method.upper()} request to {url}: {str(e)}\n")
        return None

def test_for_idor(original_resp, modified_resp, method, url, verbose=False):
    """Test for IDOR vulnerability by comparing response statuses, excluding 3xx redirects."""
    # Check if the response status codes are the same and are not in the 3xx range
    if original_resp.status_code == modified_resp.status_code and not (300 <= original_resp.status_code < 400):
        if verbose:
            print("\n*** ALERT: Potential IDOR Vulnerability Detected ***")
            print(f"Endpoint: {method.upper()} {url}")
            print(f"Original Response: {original_resp.status_code}")
            print(f"Altered Response: {modified_resp.status_code}")
            print("This vulnerability may allow unauthorized access to sensitive data!\n")
            print(f"Original Response Body:\n{original_resp.text}\n")
            print(f"Altered Response Body:\n{modified_resp.text}\n")
        return True  # Alert triggered
    return False  # No alert

def test_for_authentication_bypass(original_resp, bypass_resp, method, url, verbose=False):
    """Test for authentication bypass by comparing response statuses, excluding 3xx redirects."""
    # Check if the response status codes are the same and are not in the 3xx range
    if original_resp.status_code == bypass_resp.status_code and not (300 <= original_resp.status_code < 400):
        if verbose:
            print("\n*** ALERT: Potential Authentication Bypass Detected ***")
            print(f"Endpoint: {method.upper()} {url}")
            print(f"Original Response: {original_resp.status_code}")
            print(f"Bypass Response: {bypass_resp.status_code}")
            print("This issue may allow unauthorized access to protected endpoints!\n")
            print(f"Original Response Body:\n{original_resp.text}\n")
            print(f"Bypass Response Body:\n{bypass_resp.text}\n")
        return True  # Alert triggered
    return False  # No alert

def test_requests(all_requests, auth_headers=None, altered_headers=None, verbose=False, exclude_result_with_body=None):
    """Test requests for IDOR and authentication bypass vulnerabilities."""
    alerts = []  # List to store alerts for the summary
    for idx, request in enumerate(all_requests):
        # Print a separator between requests
        if verbose:
            print("\n" + "-"*80 + "\n")

        method = request.get('method')
        url = request.get('url')
        data = request.get('body')  # Body can be JSON, form, or other types
        headers = request.get('headers', {})  # Default to an empty dictionary if not present

        # If the body is an empty string, set it to None
        if data == '':
            data = None

        # Merge auth_headers with the current headers for the original request, ensuring no duplicates
        if auth_headers:
            headers = add_or_replace_headers(headers, auth_headers)

        # Detect and handle different body formats
        content_type = headers.get('Content-Type', '').lower()
        if 'application/json' in content_type:
            try:
                data = json.dumps(data) if isinstance(data, dict) else data
            except (TypeError, ValueError) as e:
                print(f"Invalid JSON body: {data}, Error: {str(e)}")
                continue
        elif 'application/x-www-form-urlencoded' in content_type:
            try:
                data = urlencode(data) if isinstance(data, dict) else data
            except Exception as e:
                print(f"Error encoding form data: {data}, Error: {str(e)}")
                continue

        # Send the original request
        original_resp = send_request(method, url, headers, data, verbose)
        if original_resp is None:
            continue  # Skip if the original response fails

        # Check if response body matches any of the exclusion strings
        if any(exclude_str in original_resp.text for exclude_str in exclude_result_with_body):
            continue

        # Handle testing for IDOR with altered headers (from -A input)
        if altered_headers:
            try:
                modified_headers = replace_headers(headers, altered_headers)  # Modify the headers with the altered ones
                modified_resp = send_request(method, url, modified_headers, data, verbose)
                
                if modified_resp:
                    if any(exclude_str in modified_resp.text for exclude_str in exclude_result_with_body):
                        continue

                    # Perform IDOR test and similarity check
                    if test_for_idor(original_resp, modified_resp, method, url, verbose):
                        similarity = calculate_similarity(original_resp.text, modified_resp.text)
                        alerts.append(f"IDOR detected for {method} {url}. Similarity: {similarity:.2f}%")
            except Exception as e:
                print(f"Error processing IDOR test for {url}: {str(e)}")

        # Handle authentication bypass test
        if auth_headers:
            try:
                stripped_headers = remove_specified_auth_headers(headers, auth_headers)
                bypass_resp = send_request(method, url, stripped_headers, data, verbose)
                
                if bypass_resp:
                    if any(exclude_str in bypass_resp.text for exclude_str in exclude_result_with_body):
                        continue

                    if test_for_authentication_bypass(original_resp, bypass_resp, method, url, verbose):
                        similarity = calculate_similarity(original_resp.text, bypass_resp.text)
                        alerts.append(f"Authentication bypass detected for {method} {url}. Similarity: {similarity:.2f}%")
            except Exception as e:
                print(f"Error processing Authentication Bypass test for {url}: {str(e)}")


    # Print a summary of the alerts regardless of verbose
    print("\n" + "-"*80 + "\n")
    print("\n🚨 ALERT SUMMARY 🚨")
    if alerts:
        for alert in alerts:
            print(f"   - {alert}")
    else:
        print("   - No alerts detected.")
    print("\n" + "-"*80 + "\n")


def main():
    """
    Main function to set up and execute the Advanced Web and API Tester.
    It parses command-line arguments, handles input processing, and calls appropriate functions to test web and API endpoints.
    """

    print_banner()

    # Set up the argument parser
    parser = argparse.ArgumentParser(description="IDORipper: IDOR and Authentication Bypass Tester")
    parser.add_argument("-u", "--url", help="Target URL to crawl")
    
    # Allow multiple -H options (for different headers)
    parser.add_argument("-H", "--header", action="append", help="Headers as key-value pairs (e.g., 'User-Agent: MyCustomAgent')")
    
    # Allow multiple -A options (for altered headers)
    parser.add_argument("-A", "--altered", action="append", help="Altered headers for testing")
    
    parser.add_argument("--openapi", help="Path to the OpenAPI specification file")
    parser.add_argument("--import-from-burp", help="Path to Burp Suite traffic file to import", type=str)
    parser.add_argument("--parameter", help="Key-value pairs for placeholder replacement (format: key1=value1;key2=value2)")
    parser.add_argument("--domain", nargs="*", help="Domain(s) to limit crawling to")
    parser.add_argument("--depth", type=int, default=2, help="Maximum crawl depth for site crawling")
    parser.add_argument("--exclude", nargs="*", default=[], help="URLs to exclude from crawling")
    parser.add_argument("--exclude-result-with-body", nargs="*", default=[], help="Exclude responses containing specified body content from result")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output for debugging")
    args = parser.parse_args()

    # Parse the original and altered headers
    original_headers = parse_headers(args.header) if args.header else {}
    altered_headers = parse_headers(args.altered) if args.altered else {}

    # Parse placeholder replacement parameters if provided
    parameters = {}
    if args.parameter:
        try:
            # Split and parse key-value pairs from the input string (e.g., "key1=value1;key2=value2")
            parameters = {k: v for k, v in (param.split('=') for param in args.parameter.split(";"))}
        except ValueError as e:
            print("\n🚨 ERROR: Unable to parse parameters!")
            print(f"❌ DETAILS: {e}\n")
            return

    # List to hold all captured requests
    all_requests = []

    # If a URL is provided, crawl the site and gather detected requests
    if args.url:
        try:
            print(f"\n🌐 Starting site crawl: {args.url}")
            print("🔍 Crawling in progress... Please wait.\n")
            combined_requests = crawl_site_playwright(args.url, original_headers, args.domain, args.exclude, args.depth, args.verbose)  # Changed domains to domain
            for request in combined_requests:
                all_requests.append({
                    "method": request["method"],
                    "url": request["url"],
                    "headers": request["headers"],
                    "body": request.get("body", "")
                })
            print("✅ Crawl completed successfully!\n")
        except Exception as e:
            print("\n🚨 ERROR: Unable to crawl site!")
            print(f"❌ URL: {args.url}")
            print(f"❌ DETAILS: {e}\n")
            return

    # If an OpenAPI spec file is provided, load it and extract API requests
    if args.openapi:
        try:
            print(f"\n📄 Loading OpenAPI specification: {args.openapi}")
            spec = load_openapi_spec(args.openapi)
            print("🔍 Extracting API requests... Please wait.\n")
            api_requests = extract_api_targets(spec, parameters, args.exclude)
            for api_request in api_requests:
                all_requests.append({
                    "method": api_request["method"],
                    "url": api_request["url"],
                    "headers": original_headers,
                    "body": api_request.get("body", "")
                })
            print("✅ API extraction completed successfully!\n")
        except Exception as e:
            print("\n🚨 ERROR: Unable to load OpenAPI specification!")
            print(f"❌ FILE: {args.openapi}")
            print(f"❌ DETAILS: {e}\n")
            return

    # If a Burp Suite traffic file is provided, import the traffic and add the requests
    if args.import_from_burp:
        try:
            print(f"\n📥 Importing requests from Burp Suite traffic: {args.import_from_burp}")
            burp_requests = extract_requests_from_burp(args.import_from_burp, args.domain, args.exclude)  # Changed domains to domain
            for request in burp_requests:
                all_requests.append({
                    "method": request["method"],
                    "url": request["url"],
                    "headers": request["headers"],
                    "body": request["body"]
                })
            print("✅ Burp Suite traffic imported successfully!\n")
        except Exception as e:
            print("\n🚨 ERROR: Unable to import Burp Suite traffic!")
            print(f"❌ FILE: {args.import_from_burp}")
            print(f"❌ DETAILS: {e}\n")
            return

    # Replace placeholders in all requests if parameters are provided
    if parameters:
        print("\n🔄 Replacing placeholders in requests...")
        all_requests = replace_placeholders(all_requests, parameters, args.verbose)
        all_requests = replace_parameters(all_requests, parameters, args.verbose)
        print("✅ Placeholder replacement completed!\n")

    # Display all URLs in all_requests
    if all_requests:
        print("\n🔗 The following URLs will be tested:")
        for idx, request in enumerate(all_requests, start=1):
            print(f"  {idx}. {request['url']}")

    # Run tests on the gathered requests
    print("\n🚀 Running tests on all gathered requests...")
    test_requests(all_requests, original_headers, altered_headers, args.verbose, args.exclude_result_with_body)
    print("✅ All tests completed successfully! 🎉\n")


if __name__ == "__main__":
    main()