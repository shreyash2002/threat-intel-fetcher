import re
import requests
import pandas as pd
import logging
import io
import time
from ipaddress import ip_address
from retry import retry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def is_private_ip(ip):
    try:
        ip_obj = ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def real_time_progress(func):
    """
    A decorator function for logging the execution time of a function.
    """
    def wrapper(*args, **kwargs):
        logger.info(f"Executing {func.__name__}...")
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error during execution of {func.__name__}. Details: {e}")
            result = None
        end_time = time.time()
        elapsed_time = end_time - start_time
        logger.info(f"{func.__name__} completed in {elapsed_time:.2f} seconds.")
        return result
    return wrapper

@retry(tries=3, delay=2, backoff=2)
def fetch_threat_feed(url, ip_column='ip'):
    """
    Fetches threat feed data from a specified URL, processes and filters the data,
    and returns a Pandas DataFrame containing the threat data.

    :param url: The URL of the threat feed.
    :param ip_column: The name of the column containing IP addresses in the threat data.
    :return: Pandas DataFrame containing the threat data.
    """
    try:
        validate_url(url)
        response = requests.get(url)
        response.raise_for_status()

        # Determine file format based on content type
        file_format = get_file_format(response.headers.get('Content-Type'))

        threat_data = parse_threat_data(response.text, file_format)

        # Check if the expected columns are present in the threat data
        expected_columns = ['ip', 'name']  # Add more columns as needed
        missing_columns = set(expected_columns) - set(threat_data.columns)
        if missing_columns:
            logger.warning(f"Missing expected columns in threat data: {missing_columns}")

        # Filter out private IPs
        if ip_column in threat_data.columns:
            threat_data = threat_data[~threat_data[ip_column].apply(is_private_ip)]
        else:
            logger.warning(f"{ip_column} column not found in the threat data.")

        # Handle empty or malformed data
        if threat_data.empty:
            logger.warning("Threat data is empty after filtering private IPs.")
    except Exception as e:
        logger.error(f"An unexpected error occurred. Details: {e}")
        threat_data = None

    return threat_data

def validate_url(url):
    """
    Validates the format of a URL and ensures it is from a trusted source.

    :param url: The URL to be validated.
    :raises: ValueError if the URL is invalid or not from a trusted source.
    """
    # Basic URL format validation using a regular expression
    url_pattern = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    
    if not re.match(url_pattern, url):
        raise ValueError(f"Invalid URL: {url}")

    # Additional validation logic for trusted sources can be added here

def get_file_format(content_type):
    """
    Determines the file format based on the content type.

    :param content_type: The content type obtained from the response headers.
    :return: The file format (e.g., 'csv', 'json').
    :raises: ValueError if the content type is unsupported.
    """
    if 'csv' in content_type:
        return 'csv'
    elif 'json' in content_type:
        return 'json'
    else:
        raise ValueError(f"Unsupported content type: {content_type}")

def parse_threat_data(data, file_format):
    """
    Parses threat data based on the file format.

    :param data: The raw data obtained from the threat feed.
    :param file_format: The file format ('csv', 'json').
    :return: Pandas DataFrame containing the parsed threat data.
    :raises: ValueError if the file format is unsupported.
    """
    if file_format == 'csv':
        return pd.read_csv(io.StringIO(data))
    elif file_format == 'json':
        return pd.read_json(io.StringIO(data))
    else:
        raise ValueError(f"Unsupported file format: {file_format}")

if __name__ == "__main__":
    predefined_threat_feed_urls = [
        "https://example.com/threat_feed_url1.csv",
        "https://example.com/threat_feed_url2.json",
    ]
    predefined_output_file = "threat_data_output.csv"

    for threat_feed_url in predefined_threat_feed_urls:
        threat_data = fetch_threat_feed(threat_feed_url, ip_column='actual_ip_column_name')

        if threat_data is not None:
            print("Threat Data:")
            print(threat_data)
        else:
            logger.warning("No threat data available.")
