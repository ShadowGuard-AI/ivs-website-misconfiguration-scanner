import argparse
import logging
import os
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import subprocess
import pkg_resources

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="A simple infrastructure vulnerability scanner focused on common misconfigurations."
    )

    parser.add_argument("target_url", help="The target website URL to scan.")
    parser.add_argument(
        "--crawl_depth", type=int, default=3, help="Maximum depth to crawl (default: 3)."
    )
    parser.add_argument(
        "--output_file",
        help="File to save scan results (default: console output).",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose output."
    )

    return parser


def check_env_files(url):
    """
    Checks for exposed .env files at common locations on the target website.

    Args:
        url (str): The base URL of the website.

    Returns:
        list: A list of URLs where .env files were found.
    """
    env_paths = [".env", ".env.example", "config/.env", "application/.env"]
    found_env_files = []
    for path in env_paths:
        env_url = urljoin(url, path)
        try:
            response = requests.get(env_url, timeout=5)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            if "APP_KEY" in response.text:  # Simple heuristic to identify valid .env
                logging.warning(f"Potential .env file found at: {env_url}")
                found_env_files.append(env_url)
            else:
                logging.debug(f"Checked {env_url}, but it doesn't seem to be a valid .env file.")


        except requests.exceptions.RequestException as e:
            logging.debug(f"Error checking {env_url}: {e}")

    return found_env_files

def check_admin_panels(url):
    """
    Checks for common admin panels on the target website.

    Args:
        url (str): The base URL of the website.

    Returns:
        list: A list of URLs where admin panels were found.
    """
    admin_paths = ["admin", "administrator", "login", "wp-admin", "panel"]
    found_admin_panels = []
    for path in admin_paths:
        admin_url = urljoin(url, path)
        try:
            response = requests.get(admin_url, timeout=5)
            response.raise_for_status() # Raise HTTPError for bad responses
            if response.status_code == 200 or response.status_code == 403: # Check for valid status codes
                logging.warning(f"Potential admin panel found at: {admin_url}")
                found_admin_panels.append(admin_url)
        except requests.exceptions.RequestException as e:
            logging.debug(f"Error checking {admin_url}: {e}")
    return found_admin_panels


def get_installed_software_versions(url):
    """
    Attempts to identify installed software versions by analyzing HTML source code.
    This is a basic implementation and may need more sophisticated techniques.
    """
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check for common meta tags and comments that might reveal version info
        version_info = []
        for meta in soup.find_all('meta'):
            if 'name' in meta.attrs and 'generator' in meta.attrs['name'].lower():
                if 'content' in meta.attrs:
                    version_info.append(f"Generator: {meta.attrs['content']}")

        # Search for WordPress version hints
        if "wp-content" in response.text:
            version_info.append("WordPress site detected")

            # Check for a generator tag which usually includes WordPress version
            generator_tag = soup.find("meta", {"name": "generator"})
            if generator_tag:
                version_info.append(f"WordPress Generator tag: {generator_tag['content']}")

            # Attempt to find version in wp-includes/version.php (offensive approach!)
            version_php_url = urljoin(url, "wp-includes/version.php")
            try:
                version_php_response = requests.get(version_php_url, timeout=5)
                version_php_response.raise_for_status()
                if "wp_version =" in version_php_response.text:
                    version_line = [line for line in version_php_response.text.splitlines() if "wp_version =" in line][0]
                    version = version_line.split("=")[1].strip().replace(";", "").replace("'", "").strip()
                    version_info.append(f"WordPress Version from wp-includes/version.php: {version}")

            except requests.exceptions.RequestException:
                logging.debug("wp-includes/version.php not found or inaccessible")

        if version_info:
            return version_info
        else:
            return ["No version information found."]

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching or parsing the page: {e}")
        return ["Error fetching page."]


def crawl_website(url, depth=3):
    """
    Crawls the website to discover URLs. Very basic implementation.

    Args:
        url (str): The base URL to start crawling from.
        depth (int): The maximum depth to crawl.

    Returns:
        set: A set of discovered URLs.
    """
    visited = set()
    to_visit = [(url, 0)]  # (URL, depth)

    while to_visit:
        current_url, current_depth = to_visit.pop(0)
        if current_url in visited or current_depth > depth:
            continue

        visited.add(current_url)
        logging.info(f"Crawling: {current_url} (Depth: {current_depth})")

        try:
            response = requests.get(current_url, timeout=5)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(current_url, link['href'])
                # Only crawl links within the same domain
                if urlparse(absolute_url).netloc == urlparse(url).netloc:
                    to_visit.append((absolute_url, current_depth + 1))

        except requests.exceptions.RequestException as e:
            logging.debug(f"Error crawling {current_url}: {e}")

    return visited


def main():
    """
    Main function to execute the infrastructure vulnerability scanner.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    target_url = args.target_url.rstrip('/')  # Remove trailing slash for consistency
    output_file = args.output_file
    crawl_depth = args.crawl_depth

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.info(f"Starting scan on: {target_url}")

    try:

        if output_file:
            # Redirect output to file
            sys.stdout = open(output_file, "w")

        print(f"Scanning {target_url}...")

        # Crawl the website
        print("\nCrawling website...")
        discovered_urls = crawl_website(target_url, crawl_depth)
        print(f"Found {len(discovered_urls)} URLs during crawling.")

        # Check for .env files
        print("\nChecking for .env files...")
        env_files = check_env_files(target_url)
        if env_files:
            print("Potentially exposed .env files found:")
            for url in env_files:
                print(f"- {url}")
        else:
            print("No exposed .env files found.")

        # Check for admin panels
        print("\nChecking for common admin panels...")
        admin_panels = check_admin_panels(target_url)
        if admin_panels:
            print("Potential admin panels found:")
            for url in admin_panels:
                print(f"- {url}")
        else:
            print("No common admin panels found.")

        # Check for installed software versions
        print("\nIdentifying software versions...")
        version_info = get_installed_software_versions(target_url)
        print("Software Version Information:")
        for info in version_info:
            print(f"- {info}")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        if output_file:
            sys.stdout.close()
            sys.stdout = sys.__stdout__  # Restore stdout

        logging.info("Scan complete.")


if __name__ == "__main__":
    main()