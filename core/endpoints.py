import logging
import asyncio
import httpx
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import List, Dict, Any
from core.utils import setup_logging, fetch_url # Assuming fetch_url is in utils

class EndpointDiscoverer:
    """
    Discovers endpoints on a target URL by crawling, parsing HTML,
    and optionally brute-forcing common paths.
    """
    def __init__(self, args, client: httpx.AsyncClient, common_paths: List[str] = None):
        """
        Initializes the EndpointDiscoverer.

        Args:
            args (argparse.Namespace): Command-line arguments.
            client (httpx.AsyncClient): An initialized httpx.AsyncClient instance.
            common_paths (List[str], optional): A list of common paths to brute-force.
        """
        self.args = args
        self.client = client # Store the shared httpx client
        self.common_paths = common_paths if common_paths is not None else []
        setup_logging(args.verbose)
        self.logger = logging.getLogger(__name__)
        self.logger.info("EndpointDiscoverer initialized.")
        self.discovered_endpoints = set() # Use a set to store unique endpoints

    async def _crawl_page(self, url: str, depth: int, max_depth: int) -> List[str]:
        """
        Recursively crawls a single page to find links.

        Args:
            url (str): The URL to crawl.
            depth (int): Current crawling depth.
            max_depth (int): Maximum crawling depth.

        Returns:
            List[str]: A list of new URLs found on the page.
        """
        if depth > max_depth or url in self.discovered_endpoints:
            return []

        self.logger.debug(f"Crawling: {url} (Depth: {depth}/{max_depth})")
        self.discovered_endpoints.add(url) # Mark as visited

        response = await fetch_url(url, client=self.client)
        if not response or not response.is_success:
            self.logger.debug(f"Failed to fetch {url} for crawling.")
            return []

        new_urls = []
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all 'a' (anchor) tags and 'script' tags for URLs
        for tag in soup.find_all(['a', 'script', 'link', 'img']):
            href = tag.get('href')
            src = tag.get('src')

            link = href or src
            if link:
                # Resolve relative URLs
                full_url = urljoin(url, link)
                parsed_full_url = urlparse(full_url)

                # Only include URLs on the same domain or subdomains for deep crawl
                if parsed_full_url.netloc == urlparse(self.args.url).netloc or \
                   parsed_full_url.netloc.endswith('.' + urlparse(self.args.url).netloc):
                    # Filter out mailto, tel, etc. and non-HTTP/HTTPS schemes
                    if parsed_full_url.scheme in ['http', 'https']:
                        # Normalize URL (remove fragments)
                        normalized_url = parsed_full_url._replace(fragment="").geturl()
                        if normalized_url not in self.discovered_endpoints:
                            new_urls.append(normalized_url)
                            self.logger.debug(f"  Found new URL: {normalized_url}")
        return new_urls

    async def _brute_force_paths(self, base_url: str) -> List[str]:
        """
        Attempts to discover endpoints by brute-forcing common paths.

        Args:
            base_url (str): The base URL to append paths to.

        Returns:
            List[str]: A list of discovered valid paths.
        """
        if not self.common_paths:
            self.logger.warning("No common paths provided for brute-forcing.")
            return []

        self.logger.info(f"Starting path brute-forcing for: {base_url} with {len(self.common_paths)} paths.")
        found_paths = []
        tasks = []

        for path in self.common_paths:
            full_url = urljoin(base_url, path)
            tasks.append(self._check_path_existence(full_url))

        results = await asyncio.gather(*tasks)

        for url, exists in results:
            if exists:
                found_paths.append(url)
                self.logger.info(f"  [FOUND] Valid path: {url}")
            else:
                self.logger.debug(f"  [NOT FOUND] Path: {url}")

        self.logger.info(f"Path brute-forcing completed. Found {len(found_paths)} paths.")
        return found_paths

    async def _check_path_existence(self, url: str) -> (str, bool):
        """
        Checks if a given URL path exists by making a HEAD request.

        Args:
            url (str): The URL to check.

        Returns:
            (str, bool): The URL and True if it exists (status 200), False otherwise.
        """
        try:
            response = await self.client.head(url, follow_redirects=True)
            return url, response.status_code == 200
        except httpx.RequestError as exc:
            self.logger.debug(f"Error checking path {url}: {exc}")
            return url, False
        except Exception as e:
            self.logger.debug(f"Unexpected error checking path {url}: {e}")
            return url, False

    async def discover(self, target_url: str, deep_crawl: bool = False) -> List[str]:
        """
        Orchestrates the endpoint discovery process.

        Args:
            target_url (str): The initial URL to start discovery from.
            deep_crawl (bool): If True, perform recursive crawling.

        Returns:
            List[str]: A list of all unique discovered endpoints.
        """
        self.discovered_endpoints = set() # Reset for each new discovery run

        # Start with the target URL
        self.discovered_endpoints.add(target_url)

        # Phase 1: Initial Crawl
        self.logger.info(f"Starting initial crawl for {target_url}...")
        initial_links = await self._crawl_page(target_url, 1, 1) # Depth 1 for initial page
        for link in initial_links:
            self.discovered_endpoints.add(link)
        self.logger.info(f"Initial crawl found {len(self.discovered_endpoints)} unique endpoints.")

        # Phase 2: Deep Crawl (if enabled)
        if deep_crawl:
            self.logger.info(f"Starting deep crawling for {target_url}...")
            # Use a queue for BFS-like crawling
            queue = asyncio.Queue()
            for link in list(self.discovered_endpoints): # Add initially found links to queue
                await queue.put((link, 1)) # (url, current_depth)

            while not queue.empty():
                current_url, current_depth = await queue.get()

                if current_depth >= self.args.max_crawl_depth: # Use a max_crawl_depth from args
                    continue

                new_links = await self._crawl_page(current_url, current_depth + 1, self.args.max_crawl_depth)
                for link in new_links:
                    if link not in self.discovered_endpoints:
                        self.discovered_endpoints.add(link)
                        await queue.put((link, current_depth + 1))
            self.logger.info(f"Deep crawling completed. Total unique endpoints: {len(self.discovered_endpoints)}")

        # Phase 3: Brute-force common paths
        self.logger.info("Starting brute-force for common paths...")
        brute_forced_paths = await self._brute_force_paths(target_url)
        for path in brute_forced_paths:
            self.discovered_endpoints.add(path)
        self.logger.info(f"Brute-force completed. Total unique endpoints after brute-force: {len(self.discovered_endpoints)}")

        return list(self.discovered_endpoints)

# Example Usage (for testing purposes)
async def main_endpoint_discoverer_test():
    class MockArgs:
        def __init__(self, verbose=True, deep_crawl=True, max_crawl_depth=2):
            self.verbose = verbose
            self.deep_crawl = deep_crawl
            self.max_crawl_depth = max_crawl_depth
            self.url = "http://example.com" # Mock URL for domain check

    mock_args = MockArgs(verbose=True, deep_crawl=True, max_crawl_depth=2)

    # Create a shared client for testing
    test_client = httpx.AsyncClient(timeout=10, follow_redirects=True)

    # Mock fetch_url for testing purposes
    async def mock_fetch_url_for_endpoints(url: str, client: httpx.AsyncClient) -> httpx.Response | None:
        class MockResponse:
            def __init__(self, status_code, text, url, is_success=True):
                self.status_code = status_code
                self._text = text
                self._url = url
                self.is_success = is_success
                self.headers = {} # Add headers attribute

            @property
            def text(self):
                return self._text

            @property
            def url(self):
                return self._url

            def raise_for_status(self):
                if self.status_code >= 400:
                    raise httpx.HTTPStatusError(f"HTTP Error {self.status_code}", request=httpx.Request("GET", str(self.url)), response=self)

        if "example.com/page1" in url:
            return MockResponse(200, '<html><body><a href="/page2">Link2</a><script src="/api/data.js"></script></body></html>', url)
        elif "example.com/page2" in url:
            return MockResponse(200, '<html><body><a href="/page3">Link3</a></body></html>', url)
        elif "example.com/admin/" in url:
            return MockResponse(200, '<html><body>Admin Panel</body></html>', url)
        elif "example.com/nonexistent" in url:
            return MockResponse(404, 'Not Found', url, is_success=False)
        elif "example.com" in url: # Base URL
            return MockResponse(200, '<html><body><a href="/page1">Link1</a><a href="http://external.com">External</a></body></html>', url)
        return MockResponse(200, '<html><body>Default Page</body></html>', url)

    # Mock _check_path_existence for testing brute-force
    async def mock_check_path_existence(url: str) -> (str, bool):
        if "example.com/admin/" in url or "example.com/robots.txt" in url:
            return url, True
        return url, False

    # Temporarily patch functions for this test
    original_fetch_url = globals()['fetch_url']
    original_check_path_existence = EndpointDiscoverer._brute_force_paths # This is a bit tricky, better to mock the method directly on instance

    globals()['fetch_url'] = mock_fetch_url_for_endpoints
    EndpointDiscoverer._check_path_existence = mock_check_path_existence # Patch the method directly

    common_paths = ["/admin/", "/robots.txt", "/nonexistent"]
    discoverer = EndpointDiscoverer(mock_args, client=test_client, common_paths=common_paths)

    print("\n--- Endpoint Discovery Test ---")
    endpoints = await discoverer.discover("http://example.com", deep_crawl=True)
    print("\nDiscovered Endpoints:")
    for ep in sorted(endpoints):
        print(f"- {ep}")

    # Restore original functions
    globals()['fetch_url'] = original_fetch_url
    EndpointDiscoverer._check_path_existence = original_check_path_existence # Restore original method

    await test_client.aclose() # Close the shared client

if __name__ == "__main__":
    import sys
    # asyncio.run(main_endpoint_discoverer_test())
    print("This module is designed to be integrated into ReconX. Run `python reconx.py -u <your_url> --deep-crawl` to test the full flow.")
