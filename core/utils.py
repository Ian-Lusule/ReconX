import logging
import asyncio
import httpx
from urllib.parse import urlparse
import sys
import random

def setup_logging(verbose: bool = False):
    """
    Sets up logging for the ReconX application and returns the logger instance.

    Args:
        verbose (bool): If True, set logging level to DEBUG, otherwise INFO.

    Returns:
        logging.Logger: The configured logger instance.
    """
    log_level = logging.DEBUG if verbose else logging.INFO

    # Get the root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)

    # Clear existing handlers to prevent duplicate output
    if logger.handlers:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()

    # Add a new stream handler
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Suppress verbose output from httpx and asyncio if not in debug mode
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)

    return logger # Return the configured logger instance

async def fetch_url(url: str, client: httpx.AsyncClient = None) -> httpx.Response | None:
    """
    Fetches content from a given URL asynchronously.

    Args:
        url (str): The URL to fetch.
        client (httpx.AsyncClient, optional): An existing httpx client. If None, a new one is created.

    Returns:
        httpx.Response | None: The response object if successful, None otherwise.
    """
    _client = client if client else httpx.AsyncClient(timeout=10, follow_redirects=True)
    try:
        logging.debug(f"Fetching URL: {url}")
        response = await _client.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)
        logging.debug(f"Successfully fetched {url} with status {response.status_code}")
        return response
    except httpx.RequestError as exc:
        logging.error(f"An error occurred while requesting {exc.request.url!r}: {exc}")
    except httpx.HTTPStatusError as exc:
        logging.error(f"Error response {exc.response.status_code} while requesting {exc.request.url!r}.")
    except Exception as e:
        logging.error(f"An unexpected error occurred while fetching {url}: {e}")
    finally:
        if not client: # Close client only if it was created within this function
            await _client.aclose()
    return None

def is_valid_url(url: str) -> bool:
    """
    Checks if the given string is a valid URL.

    Args:
        url (str): The string to check.

    Returns:
        bool: True if it's a valid URL, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def get_random_user_agent() -> str:
    """
    Returns a random user-agent string to mimic different browsers.
    """
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/108.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.41",
        "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.117 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Mobile/15E148 Safari/604.1"
    ]
    return random.choice(user_agents)
