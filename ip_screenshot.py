# ip_screenshot.py

import sys
import socket
import shutil
import os
import ipaddress
import argparse
import json
from datetime import datetime
import tempfile
import ipaddress
from PIL import Image
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service


MAX_WORKERS = 20
DEFAULT_TIMEOUT = 3  # seconds


def expand_targets(targets):
    """
    Expands a list of targets (IPs or CIDR ranges) into a list of individual IP addresses.

    Args:
        targets: A list of strings, where each string is an IP address or a CIDR range.

    Returns:
        A list of individual IP addresses.
    """
    all_ips = []
    for target in targets:
        try:
            if "/" in target:
                # CIDR range
                net = ipaddress.ip_network(target, strict=False)
                all_ips.extend([str(ip) for ip in net.hosts()])
            else:
                # Single IP
                all_ips.append(target)
        except ValueError as e:
            print(f"Invalid target: {target} ({e})")
    return all_ips


def port_scan(ip, ports):
    """
    Scans a given IP address for open ports.

    Args:
        ip: The IP address to scan.
        ports: A list of ports to check.

    Returns:
        A list of open ports.
    """
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=3):
                print(f"Port open: {ip}:{port}")
                open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError, OSError):
            print(f"Port closed: {ip}:{port}")
    return open_ports


def setup_driver(ignore_ssl_errors=False, timeout=10):
    """
    Sets up the Selenium WebDriver with specified options.

    Args:
        ignore_ssl_errors: If True, SSL certificate errors will be ignored.
        timeout: The page load timeout in seconds.

    Returns:
        A tuple containing the WebDriver instance and the temporary profile directory.
    """
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-setuid-sandbox")
    # options.add_argument("--single-process") # Removing this as it can cause renderer connection issues
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--remote-debugging-port=9222")

    if ignore_ssl_errors:
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--allow-insecure-localhost") # Useful for local testing, might not impact external sites much
        options.add_argument("--allow-running-insecure-content")
        options.add_argument("--disable-web-security") # Disables same-origin policy and other security checks
        options.add_argument("--ignore-urlfetcher-cert-requests") # Ignore certificate errors for URL fetches
        # options.add_argument("--no-proxy-server") # Moved to be with other options related to ignore_ssl_errors block further up
        options.accept_insecure_certs = True # Directly set the capability

    # --- Auto-detect Chrome/Chromium binary location ---
    possible_locations = []
    if sys.platform.startswith('linux'):
        possible_locations = [
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
            "/opt/google/chrome/chrome",
        ]
    elif sys.platform == 'darwin':  # macOS
        possible_locations = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
    
    binary_location_found = None
    for loc in possible_locations:
        if os.path.exists(loc):
            binary_location_found = loc
            print(f"Found browser binary at: {binary_location_found}")
            break
    
    if binary_location_found:
        options.binary_location = binary_location_found
    else:
        # Fallback: Don't set binary_location and hope webdriver_manager finds it,
        # or print a warning if it's critical to set it.
        # For headless, it's often better to be explicit.
        print("Warning: Could not find Chrome/Chromium binary in common locations. "
              "Relying on webdriver-manager to find it or system PATH.")
        # Optionally, you could raise an error here if a specific binary is strictly required:
        # raise FileNotFoundError("Could not find Chrome/Chromium binary. Please ensure it is installed and in PATH or set a valid path.")

    # Create temp profile
    temp_profile_dir = tempfile.mkdtemp(prefix="chrome-user-data-")
    options.add_argument(f"--user-data-dir={temp_profile_dir}")

    if ignore_ssl_errors: # Adding --no-proxy-server specifically when ignoring SSL errors
        options.add_argument("--no-proxy-server")

    # Setup Chrome driver
    chromedriver_log_path = os.path.join(os.getcwd(), "chromedriver.log")
    service_args = ['--verbose']
    if ignore_ssl_errors: # To make log more useful for this specific issue
        print(f"Chromedriver verbose logging enabled at: {chromedriver_log_path}")
    
    service = Service(
        ChromeDriverManager().install(),
        service_args=service_args,
        log_path=chromedriver_log_path
    )
    driver = webdriver.Chrome(service=service, options=options)
    driver.set_page_load_timeout(timeout)

    return driver, temp_profile_dir


def create_thumbnail(image_path, size=(400, 300)):
    """
    Creates a thumbnail for a given image.

    Args:
        image_path: The path to the image file.
        size: The desired size of the thumbnail (width, height).

    Returns:
        The path to the created thumbnail, or None if an error occurred.
    """
    try:
        img = Image.open(image_path)
        img.thumbnail(size)
        base, ext = os.path.splitext(image_path)
        thumbnail_path = f"{base}_thumb{ext}"
        img.save(thumbnail_path)
        return thumbnail_path
    except Exception as e:
        print(f"Failed to create thumbnail for {image_path}: {e}")
        return None


def try_screenshot(
    driver,
    ip,
    port,
    scheme,
    output_folder,
    log_entries,
    json_entries,
    ignore_ssl_errors,
    timeout=10,
    retries=1,
):
    """
    Tries to take a screenshot of a given URL.

    Args:
        driver: The Selenium WebDriver instance.
        ip: The IP address of the target.
        port: The port number of the target.
        scheme: The protocol to use (http or https).
        output_folder: The folder where the screenshot will be saved.
        log_entries: A list to store log messages.
        json_entries: A list to store JSON data.
        ignore_ssl_errors: If True, SSL certificate errors will be ignored.
        timeout: The page load timeout in seconds.
        retries: The number of times to retry if the first attempt fails.

    Returns:
        True if the screenshot was taken successfully, False otherwise.
    """
    url = f"{scheme}://{ip}:{port}"
    filename = f"{output_folder}/{ip}_{port}_{scheme}.png"

    for attempt in range(retries + 1):  # first try + retries
        try:
            driver.set_page_load_timeout(timeout)
            driver.get(url)
            os.makedirs(output_folder, exist_ok=True)
            driver.save_screenshot(filename)
            create_thumbnail(filename)

            page_title = driver.title.strip() if driver.title else "No Title"

            # Log text output
            log_entries.append(f"SUCCESS: {url} -> {filename} | Title: {page_title}")
            print(f"Saved screenshot: {filename} | Title: {page_title}")

            # JSON structure
            json_entries.append(
                {
                    "ip": ip,
                    "port": port,
                    "protocol": scheme,
                    "screenshot": f"{ip}_{port}_{scheme}.png",
                    "title": page_title,
                }
            )

            return True  # success

        except (TimeoutException, WebDriverException) as e:
            if attempt < retries:
                print(f"Try {attempt + 1} failed: {url} - Retrying...")
            else:
                print(f"Failed: {url} - {str(e).splitlines()[0]}")
                log_entries.append(f"FAIL: {url} - {str(e).splitlines()[0]}")
                return False

        except Exception as e:
            print(f"Unexpected error loading {url}: {str(e).splitlines()[0]}")
            log_entries.append(f"ERROR: {url} - {str(e).splitlines()[0]}")
            return False

    return False


def generate_gallery(output_folder, screenshot_info):
    """
    Generates an HTML gallery of the screenshots.

    Args:
        output_folder: The folder where the gallery will be saved.
        screenshot_info: A list of log entries containing information about the screenshots.
    """
    html = ["<html><head><title>IP Screenshot Gallery</title></head><body>"]
    html.append("<h1>IP Screenshot Gallery</h1>")
    html.append("<ul>")

    for entry in screenshot_info:
        if entry.startswith("SUCCESS:"):
            parts = entry.split("->")
            if len(parts) >= 2:
                _, file_title = parts
                file_info, title_info = file_title.split("| Title:")
                filepath = file_info.strip()
                title = title_info.strip()

                filename = os.path.basename(filepath)
                thumbnail_filename = filename.replace(".png", "_thumb.png")

                # Extract original URL
                parts = filename.split("_")
                if len(parts) >= 3:
                    ip = parts[0]
                    port = parts[1]
                    protocol = parts[2].replace(".png", "")
                    url = f"{protocol}://{ip}:{port}"
                else:
                    url = "#"

                # Build HTML
                html.append(f'''
                <li>
                  <a href="{filename}">
                  <img src="{thumbnail_filename}" width="400">
                  </a><br>
                  {filename} - {title}<br>
                  <a href="{url}" target="_blank">Open site</a>
               </li>
               ''')

    html.append("</ul></body></html>")

    with open(os.path.join(output_folder, "index.html"), "w") as f:
        f.write("\n".join(html))

    print(f"Generated gallery: {output_folder}/index.html")


def save_scanlog(output_folder, log_entries):
    """
    Saves the scan log to a file.

    Args:
        output_folder: The folder where the log file will be saved.
        log_entries: A list of log messages.
    """
    with open(os.path.join(output_folder, "scanlog.txt"), "w") as f:
        f.write("\n".join(log_entries))
    print(f"Saved scanlog: {output_folder}/scanlog.txt")


def parse_args():
    """
    Parses command-line arguments.

    Returns:
        An argparse.Namespace object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Scan IPs for websites and capture screenshots."
    )
    parser.add_argument("targets", nargs="*", help="Target IP(s) or ranges")
    parser.add_argument(
        "--ports",
        default="80,443",
        help="Comma-separated list of ports to scan (default 80,443)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout for each page load in seconds (default 10)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="Number of retries per page if first load fails (default 1)",
    )
    parser.add_argument(
        "--no-ssl-check", action="store_true", help="Disable SSL certificate validation"
    )
    parser.add_argument(
        "--zip", action="store_true", help="Zip output folder after scan"
    )
    parser.add_argument(
        "--json", action="store_true", help="Save scan results as structured JSON"
    )
    parser.add_argument(
        "--input",
        help="Path to file containing list of IPs or CIDR ranges (one per line)",
    )

    # Handle no arguments
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def sanitize_folder_name(target):
    """
    Sanitizes a target string to be used as a folder name.

    Args:
        target: The target string (IP address or CIDR range).

    Returns:
        A sanitized string suitable for use as a folder name.
    """
    if "/" in target:
        base, subnet = target.split("/")
        return f"{base.replace('.', '-')}-{subnet}"
    else:
        return target.replace(".", "-")


def main_scan(
    scan_tasks,  # List of (ip, ports_for_ip) tuples
    timeout=10,
    retries=1,
    ignore_ssl_errors=False,
    zip_output=False,
    save_json=False,
):
    """
    Main scanning function that orchestrates the process of scanning targets,
    taking screenshots, and generating reports.

    Args:
        scan_tasks: A list of tuples, where each tuple is (ip_address_string, list_of_ports_to_scan_for_that_ip).
        timeout: The page load timeout in seconds.
        retries: The number of retries for screenshot attempts.
        ignore_ssl_errors: If True, SSL certificate errors will be ignored.
        zip_output: If True, the output folder will be zipped.
        save_json: If True, scan results will be saved in JSON format.
    """
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_folder = f"scan-{timestamp}"
    os.makedirs(output_folder, exist_ok=True)

    log_entries = []
    json_entries = []
    driver, temp_profile_dir = setup_driver(ignore_ssl_errors, timeout)

    try:
        for ip, current_ports in scan_tasks:
            print(f"\nScanning {ip} on ports {current_ports}...")
            open_ports = port_scan(ip, current_ports)

            for port_val in open_ports:
                if try_screenshot(
                    driver,
                    ip,
                    port_val,
                    "https",
                    output_folder,
                    log_entries,
                    json_entries,
                    ignore_ssl_errors,
                    timeout,
                    retries,
                ):
                    continue
                try_screenshot(
                    driver,
                    ip,
                    port_val,
                    "http",
                    output_folder,
                    log_entries,
                    json_entries,
                    ignore_ssl_errors,
                    timeout,
                    retries,
                )

    finally:
        driver.quit()
        shutil.rmtree(temp_profile_dir, ignore_errors=True)

        with open(os.path.join(output_folder, "scanlog.txt"), "w") as f:
            for entry in log_entries:
                f.write(entry + "\n")

        print(f"\nSaved scanlog: {output_folder}/scanlog.txt")
        generate_gallery(output_folder, log_entries)
        if zip_output:
            zip_name = shutil.make_archive(output_folder, "zip", output_folder)
            print(f"\nZipped output to: {zip_name}")
        if save_json:
            json_path = os.path.join(output_folder, "scan_results.json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(json_entries, f, indent=2, ensure_ascii=False)
            print(f"\nSaved structured JSON results: {json_path}")
        print("\nFinished!")


def main():
    """
    Main function to parse arguments and initiate the scanning process.
    """
    args = parse_args()
    default_ports_list = [int(p.strip()) for p in args.ports.split(",")]

    targets_with_ports_config = []  # List of (target_spec_str, list_of_ports_for_target_spec)

    if args.input:
        try:
            with open(args.input, "r") as f:
                lines = f.readlines()
                for line_num, line_content in enumerate(lines):
                    line_content = line_content.strip()
                    if not line_content or line_content.startswith("#"): # Ignore empty lines and comments
                        continue
                    
                    parts = [p.strip() for p in line_content.split(",")]
                    target_spec = parts[0]
                    
                    if not target_spec: # Line might be like ",80,443" which is invalid
                        print(f"Warning: Skipping invalid line {line_num+1} in input file: '{line_content}'. Target missing.")
                        continue

                    if len(parts) > 1:
                        # Ports are specified in the file for this target
                        try:
                            # Filter out empty strings that might result from trailing commas, e.g., "1.2.3.4,80,"
                            specific_ports = [int(p) for p in parts[1:] if p]
                            if not specific_ports: # e.g. line was "1.2.3.4," or "1.2.3.4, ,"
                                print(f"Warning: No valid ports found for {target_spec} in line: '{line_content}'. Using default ports.")
                                targets_with_ports_config.append((target_spec, default_ports_list))
                            else:
                                targets_with_ports_config.append((target_spec, specific_ports))
                        except ValueError:
                            print(f"Warning: Invalid port found for {target_spec} in line: '{line_content}'. Using default ports.")
                            targets_with_ports_config.append((target_spec, default_ports_list))
                    else:
                        # No ports specified in the file for this target, use default
                        targets_with_ports_config.append((target_spec, default_ports_list))
        except Exception as e:
            print(f"Failed to read input file {args.input}: {e}")
            sys.exit(1)
    else:
        # Use positional arguments from command line
        if not args.targets:
            # This case should ideally be caught by argparse if 'targets' is mandatory
            # or handled if nargs='*' allows no targets.
            # If no targets and no input file, there's nothing to scan.
            # parse_args() already exits if no args are given at all.
            # If targets is optional and none given, targets_with_ports_config will be empty.
            pass # Proceed with empty targets_with_ports_config if applicable
        for target_spec in args.targets:
            targets_with_ports_config.append((target_spec, default_ports_list))

    if not targets_with_ports_config:
        print("No targets specified. Exiting.")
        sys.exit(0)
        
    scan_tasks = []  # This will be a list of (ip_str, list_of_ports_for_ip)
    for target_spec, ports_for_spec in targets_with_ports_config:
        expanded_ips = expand_targets([target_spec])  # expand_targets expects a list of targets
        for ip in expanded_ips:
            scan_tasks.append((ip, ports_for_spec))
    
    # Deduplicate scan_tasks to ensure an IP is not scanned on the same set of ports multiple times.
    # This can happen if an IP is listed explicitly and also part of a CIDR,
    # or if the same IP:ports combo appears multiple times in the input.
    unique_scan_tasks_map = {} # Using a dict to preserve order of first encounter and allow easy port update if needed (though not strictly needed here)
    for ip, ports in scan_tasks:
        # Create a frozenset of ports for dictionary key, as lists are not hashable
        ports_tuple_sorted = tuple(sorted(list(set(ports)))) # Dedupe ports for a given IP as well
        if ip not in unique_scan_tasks_map:
            unique_scan_tasks_map[ip] = ports_tuple_sorted
        else:
            # This logic could be to merge ports if an IP is seen again.
            # For now, let's assume the first comprehensive port list encountered for an IP is fine,
            # or simply overwrite (which the current loop for set does).
            # To be robust: if an IP is listed multiple times with *different* ports,
            # we might want to scan all unique ports mentioned across all its entries.
            # Current unique_scan_tasks_set logic below will treat (ip, [80,443]) and (ip, [443,80]) as same,
            # but (ip, [80]) and (ip, [80,443]) as different tasks.
            # Let's refine deduplication to collect all unique ports for an IP.
            pass # Will be handled by the set logic below to make tasks unique

    # Refined deduplication: collect all unique ports per IP.
    ip_to_all_ports_map = {}
    for ip, ports_list in scan_tasks:
        if ip not in ip_to_all_ports_map:
            ip_to_all_ports_map[ip] = set()
        ip_to_all_ports_map[ip].update(ports_list)

    final_scan_tasks = []
    for ip, ports_set in ip_to_all_ports_map.items():
        final_scan_tasks.append((ip, sorted(list(ports_set))))


    timeout = args.timeout
    retries = args.retries
    zip_output = args.zip
    ignore_ssl_errors = args.no_ssl_check
    save_json = args.json

    if not final_scan_tasks:
        print("No valid targets to scan after processing inputs. Exiting.")
        sys.exit(0)
        
    # --- Call the organized scanner now ---
    main_scan(
        final_scan_tasks, timeout, retries, ignore_ssl_errors, zip_output, save_json
    )


if __name__ == "__main__":
    main()
