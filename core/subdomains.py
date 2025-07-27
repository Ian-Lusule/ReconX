import logging
import asyncio
import httpx
from urllib.parse import urlparse, urlunparse
from typing import List, Dict, Any
from core.utils import setup_logging # Assuming setup_logging is in utils

class SubdomainEnumerator:
    """
    Enumerates subdomains for a given target domain using a wordlist and
    making HTTP requests to check for their existence.
    """
    def __init__(self, args, client: httpx.AsyncClient, subdomain_wordlist: List[str] = None):
        """
        Initializes the SubdomainEnumerator.

        Args:
            args (argparse.Namespace): Command-line arguments.
            client (httpx.AsyncClient): An initialized httpx.AsyncClient instance.
            subdomain_wordlist (List[str], optional): A list of subdomains to test.
        """
        self.args = args
        self.client = client # Store the shared httpx client
        self.subdomain_wordlist = subdomain_wordlist if subdomain_wordlist is not None else []
        setup_logging(args.verbose)
        self.logger = logging.getLogger(__name__)
        self.logger.info("SubdomainEnumerator initialized.")

    async def _check_subdomain(self, base_domain: str, subdomain: str) -> str | None:
        """
        Checks if a subdomain resolves and is accessible via HTTP/HTTPS.

        Args:
            base_domain (str): The main domain (e.g., "example.com").
            subdomain (str): The subdomain prefix (e.g., "www", "dev").

        Returns:
            str | None: The full URL of the accessible subdomain if found, None otherwise.
        """
        full_domain = f"{subdomain}.{base_domain}"
        test_urls = [f"https://{full_domain}", f"http://{full_domain}"]

        for url in test_urls:
            try:
                self.logger.debug(f"Checking subdomain: {url}")
                response = await self.client.head(url, follow_redirects=True, timeout=5) # Use HEAD for efficiency
                if response.status_code < 400: # Consider 2xx and 3xx as successful
                    self.logger.info(f"  [FOUND] Subdomain: {url} (Status: {response.status_code})")
                    return url
            except httpx.RequestError as exc:
                self.logger.debug(f"  Subdomain check failed for {url}: {exc}")
            except Exception as e:
                self.logger.debug(f"  Unexpected error checking subdomain {url}: {e}")
        return None

    async def enumerate(self, base_domain: str) -> List[str]:
        """
        Enumerates subdomains for the given base domain.

        Args:
            base_domain (str): The main domain to enumerate subdomains for (e.g., "example.com").

        Returns:
            List[str]: A list of discovered and accessible subdomain URLs.
        """
        if not self.subdomain_wordlist:
            self.logger.warning("No subdomain wordlist provided. Subdomain enumeration skipped.")
            return []

        self.logger.info(f"Starting subdomain enumeration for: {base_domain} with {len(self.subdomain_wordlist)} words.")
        discovered_subdomains = []
        tasks = []

        for subdomain_prefix in self.subdomain_wordlist:
            tasks.append(self._check_subdomain(base_domain, subdomain_prefix))

        results = await asyncio.gather(*tasks)

        for result_url in results:
            if result_url:
                discovered_subdomains.append(result_url)

        self.logger.info(f"Subdomain enumeration completed. Found {len(discovered_subdomains)} accessible subdomains.")
        return discovered_subdomains

# Example Usage (for testing purposes)
async def main_subdomain_enumerator_test():
    class MockArgs:
        def __init__(self, verbose=True):
            self.verbose = verbose

    mock_args = MockArgs(verbose=True)

    # Create a shared client for testing
    test_client = httpx.AsyncClient(timeout=10, follow_redirects=True)

    sample_wordlist = ["www", "dev", "blog", "test"] # Example wordlist

    # Mock _check_subdomain for testing purposes
    async def mock_check_subdomain(base_domain: str, subdomain: str) -> str | None:
        if subdomain == "www" and base_domain == "example.com":
            return "https://www.example.com"
        elif subdomain == "dev" and base_domain == "example.com":
            return "http://dev.example.com"
        return None

    # Temporarily patch the method for this test
    original_check_subdomain = SubdomainEnumerator._check_subdomain
    SubdomainEnumerator._check_subdomain = mock_check_subdomain

    enumerator = SubdomainEnumerator(mock_args, client=test_client, subdomain_wordlist=sample_wordlist)

    print("\n--- Subdomain Enumeration Test ---")
    subdomains = await enumerator.enumerate("example.com")
    print("\nDiscovered Subdomains:")
    for sd in sorted(subdomains):
        print(f"- {sd}")

    # Restore original method
    SubdomainEnumerator._check_subdomain = original_check_subdomain

    await test_client.aclose() # Close the shared client

if __name__ == "__main__":
    import sys
    # asyncio.run(main_subdomain_enumerator_test())
    print("This module is designed to be integrated into ReconX. Run `python reconx.py -u <your_url> --include-subdomains` to test the full flow.")
