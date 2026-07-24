# Network Port Scanner

A fast, multithreaded TCP port scanner built entirely with the **Python 3 standard library** — no third-party dependencies required. Designed as a clean, beginner-friendly portfolio project that demonstrates networking fundamentals, concurrency, CLI design, and clean code practices.

> ⚠️ **Authorized Use Only**
> This tool is intended strictly for educational purposes and for testing systems you **own** or have **explicit, written permission** to test. Scanning networks or hosts without authorization may be illegal in your jurisdiction and may violate your network/hosting provider's terms of service. The author(s) accept no liability for misuse of this software. See [LICENSE](LICENSE) for the full disclaimer.

---

## Overview

Network Port Scanner is a command-line tool that checks whether TCP ports on a given IP address or hostname are open or closed. It uses Python's built-in `socket` module for connections, `threading` for concurrent scanning, and only the standard library throughout — making it easy to read, run, and extend without installing anything.

It's built to resemble a lightweight version of tools like `nmap` for TCP connect scans, while staying simple enough to fully understand line-by-line.

---

## Features

- 🎯 **Flexible targeting** — scan by IP address or hostname (automatically resolved via DNS)
- 🔢 **Flexible port selection**
  - Single port (`80`)
  - Port range (`1-1024`)
  - Comma-separated list (`22,80,443`)
  - Mixed (`22,80,1000-1010`)
  - Built-in "common ports" list (`common`)
- ⚡ **Multithreaded scanning** for fast results, with a configurable thread pool size
- 🏷️ **Service name detection** for well-known ports (HTTP, HTTPS, SSH, FTP, SMTP, DNS, RDP, MySQL, and more)
- 🎨 **Colored terminal output** using pure ANSI escape codes (no `colorama` or other dependencies)
- ⏱️ **Scan timing** — displays start time, end time, and total duration
- 📄 **CSV export** of results for reporting or record-keeping
- 🛡️ **Robust input validation** — gracefully handles invalid IPs, unresolvable hostnames, malformed port specs, and out-of-range ports
- 🧵 **Thread-safe result collection** using locks and a shared queue
- 📝 **Fully documented code** with docstrings and inline comments, written to PEP 8 style guidelines

---

## Installation

This project requires **Python 3.7+** and has **no external dependencies**.

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/network-port-scanner.git
cd network-port-scanner

# 2. (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

# 3. There is nothing to install — requirements.txt lists standard-library
#    modules only. You're ready to run the scanner.
```

---

## Usage

Run the scanner via `main.py`, providing a target and a port specification.

```bash
python main.py -t <target> -p <ports> [options]
```

### Arguments

| Flag | Description | Required |
|------|-------------|----------|
| `-t`, `--target` | IP address or hostname to scan | Yes |
| `-p`, `--ports` | Port(s): single, range, list, or `common` | Yes |
| `--timeout` | Socket timeout per port in seconds (default: `1.0`) | No |
| `--threads` | Max concurrent threads (default: `100`) | No |
| `--csv` | File path to export results as CSV | No |

### Examples

Scan a single port on localhost:
```bash
python main.py -t 127.0.0.1 -p 80
```

Scan a range of ports on a hostname:
```bash
python main.py -t example.com -p 1-1024
```

Scan a specific list of ports:
```bash
python main.py -t 192.168.1.10 -p 22,80,443
```

Scan the built-in list of common/well-known ports:
```bash
python main.py -t 192.168.1.10 -p common
```

Scan and export results to a CSV file:
```bash
python main.py -t 192.168.1.10 -p common --csv results.csv
```

Adjust timeout and thread count for a large scan:
```bash
python main.py -t 192.168.1.10 -p 1-65535 --timeout 0.5 --threads 300
```

---

## Sample Output

```
    =============================================
          NETWORK PORT SCANNER (Python 3)
    =============================================

DISCLAIMER: Only scan hosts you own or have explicit permission to test.

Target resolved to: 127.0.0.1
Scanning 25 port(s) with 100 thread(s)...

Scan Results for 127.0.0.1
--------------------------------------------------
Scan started : 2026-07-24 10:15:02
Scan finished: 2026-07-24 10:15:03
Duration     : 0.87 seconds
--------------------------------------------------

OPEN PORTS (2):
  [OPEN]   Port 22     -> SSH
  [OPEN]   Port 80     -> HTTP

CLOSED PORTS (23):
  21, 23, 25, 53, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433,
  1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 20

--------------------------------------------------
Total ports scanned: 25
--------------------------------------------------

Results exported to: results.csv
```

*(Colors — green for open ports, red for closed ports, yellow for warnings/info, cyan for headers — render in supporting terminals.)*

---

## Folder Structure

```
network-port-scanner/
│
├── main.py            # CLI entry point: argument parsing, output, CSV export
├── scanner.py          # PortScanner class: multithreaded scanning engine
├── utils.py             # Validation helpers, ANSI colors, common port/service map
├── requirements.txt     # Documents that only the standard library is used
├── README.md             # Project documentation (this file)
└── LICENSE                # MIT License + authorized-use disclaimer
```

---

## Future Improvements

- [ ] Add UDP port scanning support
- [ ] Add banner grabbing for open ports (to identify service versions)
- [ ] Add JSON export in addition to CSV
- [ ] Add a `--verbose` flag for real-time per-port scan progress
- [ ] Add support for scanning multiple targets (e.g. a subnet or a list from a file)
- [ ] Add a progress bar for long-running scans
- [ ] Add unit tests (`pytest`) covering `utils.py` and `scanner.py`
- [ ] Package the project for installation via `pip` (`setup.py` / `pyproject.toml`)
- [ ] Add rate limiting / stealth-scan delay options

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details, including the authorized-use disclaimer.
