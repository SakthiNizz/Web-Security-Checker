import ssl
import socket
import requests
import streamlit as st
from urllib.parse import urlparse

# Define the functions for each test case
def check_ssl_protocols(url):
    result = []
    parsed_url = urlparse(url)
    domain = parsed_url.hostname
    
    if not domain:
        result.append("Invalid URL.")
        return result
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                protocol = ssock.version()
                #result.append(f"SSL/TLS Protocols for {url}:")
                result.append(f"SSLv2    {'enabled' if 'SSLv2' in protocol else 'disabled'}")
                result.append(f"SSLv3    {'enabled' if 'SSLv3' in protocol else 'disabled'}")
                result.append(f"TLSv1.0  {'enabled' if 'TLSv1.0' in protocol else 'disabled'}")
                result.append(f"TLSv1.1  {'enabled' if 'TLSv1.1' in protocol else 'disabled'}")
                result.append(f"TLSv1.2  {'enabled' if 'TLSv1.2' in protocol else 'disabled'}")
                result.append(f"TLSv1.3  {'enabled' if 'TLSv1.3' in protocol else 'disabled'}")
    except ssl.SSLError as e:
        result.append(f"SSL Error: {e}")
    except socket.error as e:
        result.append(f"Socket Error: {e}")
    return result

def check_security_headers(url):
    security_headers = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'geolocation=(), camera=()',
    }

    result = []
    try:
        response = requests.get(url)
        headers = response.headers

        missing_headers = []
        misconfigured_headers = []

        for header, recommended_value in security_headers.items():
            if header not in headers:
                missing_headers.append(header)
            elif headers[header] != recommended_value:
                misconfigured_headers.append((header, headers[header], recommended_value))
        
        if missing_headers:
            result.append("Missing Security Headers:")
            for header in missing_headers:
                result.append(f"  - {header}")
        else:
            result.append("No missing security headers.")

        if misconfigured_headers:
            result.append("Misconfigured Security Headers:")
            for header, current_value, recommended_value in misconfigured_headers:
                result.append(f"  - {header}:")
                result.append(f"    Current: {current_value}")
                result.append(f"    Recommended: {recommended_value}")
        else:
            result.append("No misconfigured security headers.")
    except requests.RequestException as e:
        result.append(f"Request Error: {e}")
    return result

def check_host_header_vulnerability(url):
    result = []
    try:
        original_response = requests.get(url)
        original_status_code = original_response.status_code
        result.append(f"Original status code: {original_status_code}")
    except requests.RequestException as e:
        result.append(f"Error fetching the original URL: {e}")
        return result

    headers = {
        'Host': 'attacker.com'
    }
    try:
        modified_response = requests.get(url, headers=headers)
        modified_status_code = modified_response.status_code
        result.append(f"Modified status code: {modified_status_code}")

        if original_status_code != modified_status_code:
            result.append("The application is not vulnerable to Host Header Injection.")
        else:
            result.append("The application is vulnerable to Host Header Injection.")
    except requests.RequestException as e:
        result.append(f"Error fetching the URL with modified Host header: {e}")
    return result

def check_cors_vulnerabilities(url):
    result = []
    headers = {
        'Origin': 'http://example.com'
    }

    try:
        response = requests.get(url, headers=headers)
        cors_headers = response.headers

        if cors_headers.get('Access-Control-Allow-Origin') == '*':
            result.append("Vulnerability found: Access-Control-Allow-Origin is set to '*'")
        else:
            result.append("No vulnerability: Access-Control-Allow-Origin is not set to '*'")

        if cors_headers.get('Access-Control-Allow-Credentials') == 'true':
            result.append("Vulnerability found: Access-Control-Allow-Credentials is set to 'true'")
        else:
            result.append("No vulnerability: Access-Control-Allow-Credentials is not set to 'true'")

        headers['Origin'] = 'http://abs.com'
        response = requests.get(url, headers=headers)
        cors_headers = response.headers

        if cors_headers.get('Access-Control-Allow-Origin') == 'http://abs.com':
            result.append("Vulnerability found: Access-Control-Allow-Origin reflects the Origin header")
        else:
            result.append("No vulnerability: Access-Control-Allow-Origin does not reflect the Origin header")
    except requests.exceptions.RequestException as e:
        result.append(f"Request to {url} failed: {e}")
    return result

# Streamlit UI
st.title("Web Security Checker")

url = st.text_input("Enter the URL to check:")

test_options = ["SSL Scan", "Security Headers", "Host Header Vulnerability", "CORS Misconfigurations", "Run All Tests"]
selected_test = st.selectbox("Select the test to run:", test_options)

if url:
    if st.button("Run Test"):
        if selected_test == "SSL Scan" or selected_test == "Run All Tests":
            st.subheader("SSL Scan")
            ssl_result = check_ssl_protocols(url)
            for line in ssl_result:
                if "enabled" in line:
                    st.write(f"<p style='color:green'>{line}</p>", unsafe_allow_html=True)
                elif "disabled" in line:
                    st.write(f"<p style='color:red'>{line}</p>", unsafe_allow_html=True)
                else:
                    st.write(line)

        if selected_test == "Security Headers" or selected_test == "Run All Tests":
            st.subheader("Security Headers")
            headers_result = check_security_headers(url)
            for line in headers_result:
                if "Missing Security Headers:" in line or "Misconfigured Security Headers:" in line:
                    st.write(f"<p style='color:red'>{line}</p>", unsafe_allow_html=True)
                else:
                    st.write(line)

        if selected_test == "Host Header Vulnerability" or selected_test == "Run All Tests":
            st.subheader("Host Header Vulnerability")
            host_header_result = check_host_header_vulnerability(url)
            for line in host_header_result:
                if "not vulnerable" in line:
                    st.write(f"<p style='color:green'>{line}</p>", unsafe_allow_html=True)
                else:
                    st.write(f"<p style='color:red'>{line}</p>", unsafe_allow_html=True)

        if selected_test == "CORS Misconfigurations" or selected_test == "Run All Tests":
            st.subheader("CORS Misconfigurations")
            cors_result = check_cors_vulnerabilities(url)
            for line in cors_result:
                if "Vulnerability found" in line:
                    st.write(f"<p style='color:red'>{line}</p>", unsafe_allow_html=True)
                else:
                    st.write(line)
