import argparse
import logging
import os
import re
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
    # Common markers from several stacks, plus a KEY=value line shape.
    env_markers = ["APP_KEY", "DB_HOST", "DB_PASSWORD", "DB_DATABASE",
                   "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                   "SECRET_KEY", "DATABASE_URL", "MAIL_PASSWORD"]
    env_line = re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+", re.MULTILINE)
    found_env_files = []
    for path in env_paths:
        # urljoin treats the target as a directory only when it ends with a
        # slash. main strips the trailing slash, so a target with a path, such
        # as a site under /app, has that last segment replaced by these check
        # paths instead of extended by them. The checks probe the host root
        # either way, which is where these files are usually exposed.
        env_url = urljoin(url, path)
        try:
            response = requests.get(env_url, timeout=5)
            if response.status_code != 200:
                continue
            # A 200 alone proves nothing on a catch-all site, so the body has to
            # confess: a known key name, or any line shaped like an uppercase
            # assignment. A documentation page quoting an example env line trips
            # the second test. These are candidates for a human to open, not
            # confirmations.
            if any(m in response.text for m in env_markers) or env_line.search(response.text):
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
    admin_markers = ["login", "log in", "sign in", "username", "password",
                     "admin", "dashboard", "wp-login"]
    found_admin_panels = []
    for path in admin_paths:
        admin_url = urljoin(url, path)
        try:
            # No raise_for_status: a 403 is itself a meaningful answer here.
            response = requests.get(admin_url, timeout=5)
            # Admin detection uses the opposite evidence for its two cases. A 403
            # counts by itself, on the theory that something exists there worth
            # forbidding, while a 200 needs a login marker in the body because
            # catch-all sites answer 200 for every made up path.
            if response.status_code == 403:
                logging.warning(f"Potential admin panel found at: {admin_url}")
                found_admin_panels.append(admin_url)
            elif response.status_code == 200:
                body = response.text.lower()
                # A bare 200 is not enough: catch-all sites answer 200 for
                # every path. Require a login or admin marker in the body.
                if any(marker in body for marker in admin_markers):
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
    # The queue is a list popped from the front, so the crawl is breadth
    # first. Links are enqueued without a queued set; a URL linked from
    # ten pages is queued ten times and filtered by visited when popped.
    # Nothing normalises the URLs, so the same page under a fragment, a
    # trailing slash variant, and a query variant counts as three.
    to_visit = [(url, 0)]  # (URL, depth)

    while to_visit:
        current_url, current_depth = to_visit.pop(0)
        if current_url in visited or current_depth > depth:
            continue

        logging.info(f"Crawling: {current_url} (Depth: {current_depth})")

        try:
            response = requests.get(current_url, timeout=5)
            response.raise_for_status()
            # Count a URL only after a fetch actually succeeded, so a dead
            # target is not reported as one found URL.
            visited.add(current_url)
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(current_url, link['href'])
                # Only crawl links within the same domain
                # Same domain means the exact netloc string, port included. A link to
                # a subdomain, or to the same host on another port, is outside the
                # crawl, and the start URL's netloc is reparsed for every link.
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

    # Build the report in memory. It is written to the output file only
    # after the scan completes, so a failed scan never truncates or
    # replaces a pre-existing output file.
    lines = []
    try:
        lines.append(f"Scanning {target_url}...")
        lines.append("\nCrawling website...")
        discovered_urls = crawl_website(target_url, crawl_depth)
        if not discovered_urls:
            logging.error("Scan failed: no page could be fetched from the target.")
            print("Scan failed: no page could be fetched from the target.")
            sys.exit(1)
        lines.append(f"Found {len(discovered_urls)} URLs during crawling.")

        lines.append("\nChecking for .env files...")
        env_files = check_env_files(target_url)
        if env_files:
            lines.append("Potentially exposed .env files found:")
            for url in env_files:
                lines.append(f"- {url}")
        else:
            lines.append("No exposed .env files found.")

        lines.append("\nChecking for common admin panels...")
        admin_panels = check_admin_panels(target_url)
        if admin_panels:
            lines.append("Potential admin panels found:")
            for url in admin_panels:
                lines.append(f"- {url}")
        else:
            lines.append("No common admin panels found.")

        lines.append("\nIdentifying software versions...")
        version_info = get_installed_software_versions(target_url)
        lines.append("Software Version Information:")
        for info in version_info:
            lines.append(f"- {info}")

    except SystemExit:
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        print(f"Scan failed: {e}")
        sys.exit(1)

    report = "\n".join(lines) + "\n"
    if output_file:
        tmp_path = os.path.join(os.path.dirname(os.path.abspath(output_file)),
                                os.path.basename(output_file) + ".tmp")
        try:
            with open(tmp_path, "w") as fh:
                fh.write(report)
            os.replace(tmp_path, output_file)
        except OSError as e:
            logging.error(f"Could not write output file: {e}")
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
            sys.exit(1)
    else:
        print(report, end="")

    logging.info("Scan complete.")


if __name__ == "__main__":
    main()