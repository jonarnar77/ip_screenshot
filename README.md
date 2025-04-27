# IP Screenshot Scanner

IP Screenshot Scanner is a simple, flexible, and fast tool for scanning IP addresses or ranges,
capturing website screenshots (on specified ports), and generating a fast-loading thumbnail gallery.

---

## Features

- Capture full-page website screenshots automatically
- Scan individual IPs, CIDR ranges, or lists from a file
- Clickable thumbnails linked to full screenshots and live sites
- Structured JSON output (optional)
- Auto-ZIP scan results (optional)
- SSL certificate error ignoring (optional)
- Fast scanning with retries and custom timeouts

---

## Requirements

- Python 3.8+
- Chrome or Chromium installed (headless mode)
- ChromeDriver (installed automatically)
- Install Python dependencies:

pip install -r requirements.txt

or install the package:

pip install .

---

## Installation

git clone https://github.com/yourname/ip_screenshot.git
cd ip_screenshot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

Or, to install it properly as a CLI tool:

pip install .

After that you can just run:

ip-screenshot ...

from anywhere!

---

## Usage

### Scanning IPs or Ranges

ip-screenshot 8.8.8.8 1.1.1.1 --no-ssl-check --zip --json
ip-screenshot 10.0.0.0/24 --ports=80,443,8443 --timeout=15 --retries=2

### Scanning from an Input File

ip-screenshot --input targets.txt --no-ssl-check --zip --json

(Where targets.txt contains one IP or CIDR per line.)

---

## Options

| Flag | Description |
| --- | --- |
| targets | IP addresses or CIDR ranges to scan (positional) |
| --ports | Comma-separated list of ports (default: 80,443) |
| --timeout | Page load timeout in seconds (default: 10) |
| --retries | Number of retries per page (default: 1) |
| --no-ssl-check | Ignore SSL certificate errors |
| --zip | ZIP output folder after scan |
| --json | Save structured JSON scan results |
| --input | Load targets from a file (one per line) |

---

## Output

Each scan produces:

- Full-size screenshots
- Thumbnails (*_thumb.png) for faster browsing
- A scanlog.txt text log
- An index.html gallery
- (optional) scan_results.json structured output
- (optional) scan-YYYYMMDD-HHMMSS.zip archive

---

## License

This project is licensed under the MIT License — see LICENSE.

---

## Author

Created with ❤️  by Jon Arnar Jonsson.

