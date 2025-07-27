import logging
import asyncio
import ssl
import socket
import datetime
import httpx
from urllib.parse import urlparse
from typing import Dict, Any, List
from core.utils import setup_logging # Assuming setup_logging is in utils

class SSLAnalyzer:
    """
    Analyzes SSL/TLS configurations of a target URL.
    This includes checking certificate details, expiry, and basic security properties.
    """
    def __init__(self, args, client: httpx.AsyncClient):
        """
        Initializes the SSLAnalyzer.

        Args:
            args (argparse.Namespace): Command-line arguments.
            client (httpx.AsyncClient): An initialized httpx.AsyncClient instance.
        """
        self.args = args
        self.client = client # Store the shared httpx client
        setup_logging(args.verbose)
        self.logger = logging.getLogger(__name__)
        self.logger.info("SSLAnalyzer initialized.")

    async def analyze(self, url: str) -> Dict[str, Any]:
        """
        Performs SSL/TLS analysis for the given URL by leveraging httpx's SSL info.

        Args:
            url (str): The target URL (e.g., "https://example.com").

        Returns:
            Dict[str, Any]: A dictionary containing SSL/TLS analysis results.
        """
        self.logger.info(f"Starting SSL/TLS analysis for: {url}")
        ssl_info = {
            "target_url": url,
            "status": "Failed",
            "certificate_details": {},
            "warnings": [],
            "errors": []
        }

        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        if parsed_url.scheme != 'https':
            ssl_info["errors"].append("URL is not HTTPS. Skipping SSL analysis.")
            ssl_info["status"] = "Skipped (Not HTTPS)"
            self.logger.warning(f"Skipping SSL analysis for {url}: Not an HTTPS URL.")
            return ssl_info

        try:
            # Use httpx to make a request and get SSL info
            # A HEAD request is often sufficient to establish connection and get SSL info
            response = await self.client.head(url, follow_redirects=True, timeout=15)
            response.raise_for_status() # Raise an exception for 4xx/5xx responses

            if response.ssl_info:
                cert = response.ssl_info.peercert # This is the dictionary representation of the peer certificate
                ssl_info["certificate_details"] = self._parse_cert_details(cert)
                ssl_info["status"] = "Success"

                # Perform checks
                self._check_expiry(ssl_info["certificate_details"], ssl_info["warnings"], ssl_info["errors"])
                self._check_hostname_match(hostname, ssl_info["certificate_details"], ssl_info["errors"])
                self._check_common_security_issues(ssl_info["certificate_details"], ssl_info["warnings"])

                self.logger.info(f"SSL/TLS analysis completed for {url}. Status: {ssl_info['status']}")
            else:
                ssl_info["errors"].append("No SSL information available from the response.")
                ssl_info["status"] = "No SSL Info"
                self.logger.error(f"SSL analysis failed for {url}: No SSL info from httpx.")

        except httpx.RequestError as exc:
            ssl_info["errors"].append(f"Request error during SSL analysis: {exc}")
            ssl_info["status"] = "Request Error"
            self.logger.error(f"SSL analysis request error for {url}: {exc}")
        except httpx.HTTPStatusError as exc:
            ssl_info["errors"].append(f"HTTP error {exc.response.status_code} during SSL analysis: {exc.response.text}")
            ssl_info["status"] = "HTTP Error"
            self.logger.error(f"SSL analysis HTTP error for {url} - Status {exc.response.status_code}: {exc.response.text}")
        except Exception as e:
            ssl_info["errors"].append(f"An unexpected error occurred during SSL analysis: {e}")
            ssl_info["status"] = "Unexpected Error"
            self.logger.error(f"An unexpected error occurred during SSL analysis for {url}: {e}")

        return ssl_info

    def _parse_cert_details(self, cert: Dict[str, Any]) -> Dict[str, Any]:
        """Parses the raw certificate dictionary (from ssl.SSLObject.peercert) into a more readable format."""
        details = {}
        if cert:
            # The 'subject' and 'issuer' are lists of tuples, convert to dict for easier access
            details["subject"] = dict(x[0] for x in cert.get('subject', ()))
            details["issuer"] = dict(x[0] for x in cert.get('issuer', ()))
            details["version"] = cert.get('version')
            details["serialNumber"] = cert.get('serialNumber')
            details["notBefore"] = cert.get('notBefore')
            details["notAfter"] = cert.get('notAfter')
            details["signatureAlgorithm"] = cert.get('signatureAlgorithm')

            # Subject Alternative Names (SANs) are typically in 'subjectAltName'
            alt_names = []
            for ext in cert.get('subjectAltName', []):
                if ext[0] == 'DNS': # Only interested in DNS entries for hostname matching
                    alt_names.append(ext[1])
            details["subjectAltName"] = alt_names

            # Public key information is not directly in 'peercert' dict, often requires x509 parsing
            # For now, we'll leave this empty or indicate it's not directly available here.
            details["public_key_info"] = {}

        return details

    def _check_expiry(self, cert_details: Dict[str, Any], warnings: List[str], errors: List[str]):
        """Checks certificate expiry status."""
        not_after_str = cert_details.get("notAfter")
        if not_after_str:
            try:
                # Format from ssl.getpeercert() is usually like 'Jul 26 09:33:04 2026 GMT'
                expiry_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                today = datetime.datetime.utcnow()

                cert_details["expiry_date"] = expiry_date.strftime('%Y-%m-%d %H:%M:%S UTC')

                if expiry_date < today:
                    errors.append(f"Certificate has expired on {expiry_date.date()}.")
                    cert_details["expiry_status"] = "Expired"
                else:
                    days_left = (expiry_date - today).days
                    cert_details["days_until_expiry"] = days_left
                    if days_left < 30:
                        warnings.append(f"Certificate expires in {days_left} days. (Less than 30 days)")
                        cert_details["expiry_status"] = "Expiring Soon"
                    else:
                        cert_details["expiry_status"] = "Valid"
            except ValueError:
                warnings.append(f"Could not parse certificate expiry date: {not_after_str}")
                cert_details["expiry_status"] = "Unknown (Date Parse Error)"
            except Exception as e:
                warnings.append(f"Error checking expiry: {e}")
                cert_details["expiry_status"] = "Unknown (Error)"
        else:
            warnings.append("Certificate 'notAfter' field not found.")
            cert_details["expiry_status"] = "Unknown (No Date)"

    def _check_hostname_match(self, hostname: str, cert_details: Dict[str, Any], errors: List[str]):
        """Checks if the hostname matches the certificate's common name or subject alternative names."""
        common_name = cert_details.get("subject", {}).get("commonName")
        subject_alt_names = cert_details.get("subjectAltName", [])

        match = False
        if common_name:
            if self._match_wildcard_hostname(hostname, common_name):
                match = True

        if not match:
            for san in subject_alt_names:
                if self._match_wildcard_hostname(hostname, san):
                    match = True
                    break

        if not match:
            errors.append(f"Hostname '{hostname}' does not match certificate common name ('{common_name}') or subject alternative names ('{', '.join(subject_alt_names)}').")

    def _match_wildcard_hostname(self, hostname: str, pattern: str) -> bool:
        """Helper to match hostname against wildcard patterns (e.g., *.example.com)."""
        if pattern.startswith('*.') and hostname.count('.') >= 1: # Changed to >= 1 to match sub.domain.com
            # Match *.example.com against sub.example.com
            pattern_suffix = pattern[2:]
            # Ensure hostname has a part before the pattern suffix for wildcard match
            if hostname.endswith(pattern_suffix) and len(hostname) > len(pattern_suffix):
                # Check if the part before pattern_suffix is just one component
                prefix_part = hostname[:-len(pattern_suffix)].rstrip('.')
                if '.' not in prefix_part: # Ensures it's not something like sub.sub.example.com for *.example.com
                    return True
        return hostname == pattern

    def _check_common_security_issues(self, cert_details: Dict[str, Any], warnings: List[str]):
        """Checks for common SSL security issues (e.g., weak signature algorithms)."""
        signature_algorithm = cert_details.get("signatureAlgorithm")
        if signature_algorithm and "md5" in signature_algorithm.lower():
            warnings.append("Certificate uses a weak signature algorithm (MD5).")
        if signature_algorithm and "sha1" in signature_algorithm.lower():
            warnings.append("Certificate uses a weak signature algorithm (SHA1).")

        # Public key size check is more complex and usually requires parsing the full certificate
        # with a library like 'cryptography'. httpx.ssl_info.peercert does not expose key size directly.
        # For a basic check, we'd need to add a more advanced cert parsing.
        # For now, this check is omitted as it's not directly supported by peercert dict.

# Example Usage (for testing purposes)
async def main_ssl_analyzer_test():
    class MockArgs:
        def __init__(self, verbose=True):
            self.verbose = verbose

    mock_args = MockArgs(verbose=True)

    # Create a shared client for testing
    test_client = httpx.AsyncClient(timeout=10, follow_redirects=True)

    analyzer = SSLAnalyzer(mock_args, client=test_client)

    print("\n--- SSL Analyzer Test: Valid HTTPS Site ---")
    # Use a real, known good HTTPS site for testing
    results_valid = await analyzer.analyze("https://www.google.com")
    print(f"SSL Analysis Results for google.com: {results_valid}")

    print("\n--- SSL Analyzer Test: HTTP Site (should be skipped) ---")
    results_http = await analyzer.analyze("http://example.com")
    print(f"SSL Analysis Results for http://example.com: {results_http}")

    # To test expired/mismatched certificates, you would typically need to
    # mock httpx.Response.ssl_info.peercert with specific certificate dictionaries.
    # This is beyond a simple example but can be done using unittest.mock.

    await test_client.aclose() # Close the shared client

if __name__ == "__main__":
    import sys
    # asyncio.run(main_ssl_analyzer_test())
    print("This module is designed to be integrated into ReconX. Run `python reconx.py -u <your_https_url>` to test the full flow.")
