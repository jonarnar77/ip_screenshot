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
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-setuid-sandbox")
    options.add_argument("--single-process")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--remote-debugging-port=9222")

    if ignore_ssl_errors:
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--allow-insecure-localhost")
        options.add_argument("--allow-running-insecure-content")

    options.binary_location = "/usr/bin/chromium"  # or wherever your chromium binary is

    # Create temp profile
    temp_profile_dir = tempfile.mkdtemp(prefix="chrome-user-data-")
    options.add_argument(f"--user-data-dir={temp_profile_dir}")

    # Setup Chrome driver
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    driver.set_page_load_timeout(timeout)

    return driver, temp_profile_dir


def create_thumbnail(image_path, size=(400, 300)):
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
    with open(os.path.join(output_folder, "scanlog.txt"), "w") as f:
        f.write("\n".join(log_entries))
    print(f"Saved scanlog: {output_folder}/scanlog.txt")


def parse_args():
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
    if "/" in target:
        base, subnet = target.split("/")
        return f"{base.replace('.', '-')}-{subnet}"
    else:
        return target.replace(".", "-")


def main_scan(
    target_ips,
    ports,
    timeout=10,
    retries=1,
    ignore_ssl_errors=False,
    zip_output=False,
    save_json=False,
):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_folder = f"scan-{timestamp}"
    os.makedirs(output_folder, exist_ok=True)

    log_entries = []
    json_entries = []
    driver, temp_profile_dir = setup_driver(ignore_ssl_errors, timeout)

    try:
        for ip in target_ips:
            print(f"\nScanning {ip} on ports {ports}...")
            open_ports = port_scan(ip, ports)

            for port in open_ports:
                if try_screenshot(
                    driver,
                    ip,
                    port,
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
                    port,
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
    args = parse_args()

    if args.input:
        # Read from file
        try:
            with open(args.input, "r") as f:
                lines = f.readlines()
                targets = [line.strip() for line in lines if line.strip()]
        except Exception as e:
            print(f"Failed to read input file {args.input}: {e}")
            sys.exit(1)
    else:
        # Use positional arguments
        targets = args.targets

    target_ips = expand_targets(targets)
    ports = [int(p.strip()) for p in args.ports.split(",")]
    timeout = args.timeout
    retries = args.retries
    zip_output = args.zip
    ignore_ssl_errors = args.no_ssl_check
    save_json = args.json

    # --- Call the organized scanner now ---
    main_scan(
        target_ips, ports, timeout, retries, ignore_ssl_errors, zip_output, save_json
    )


if __name__ == "__main__":
    main()
