#!/usr/bin/env python3
"""
main.py
-------
Command-line entry point for the Network Port Scanner.

This script handles:
    * Parsing command-line arguments (argparse)
    * Validating the target and port inputs
    * Running the scan via the PortScanner class
    * Printing colored, formatted results to the terminal
    * Optionally exporting results to a CSV file

DISCLAIMER / AUTHORIZED USE ONLY
---------------------------------
This tool is provided for educational purposes and for testing systems
you own or have explicit, written permission to test. Scanning networks
or hosts without authorization may be illegal in your jurisdiction and
may violate the terms of service of your network or hosting provider.
The author(s) of this project accept no liability for misuse of this
software. By using this tool, you agree that you are solely responsible
for ensuring you have the right to scan the specified target.

Usage examples:
    python main.py -t 127.0.0.1 -p 80
    python main.py -t example.com -p 1-1024
    python main.py -t 192.168.1.10 -p common --csv results.csv
"""

import argparse
import csv
import socket
import sys
from datetime import datetime

from scanner import PortScanner
from utils import Colors, validate_target, parse_ports, format_duration


def print_banner() -> None:
    """Print a simple ASCII banner and the authorized-use disclaimer."""
    banner = f"""{Colors.CYAN}{Colors.BOLD}
    =============================================
          NETWORK PORT SCANNER (Python 3)
    =============================================
    {Colors.RESET}"""
    print(banner)
    print(f"{Colors.YELLOW}DISCLAIMER: Only scan hosts you own or have explicit "
          f"permission to test.{Colors.RESET}\n")


def build_arg_parser() -> argparse.ArgumentParser:
    """
    Build and return the argparse.ArgumentParser for this CLI tool.

    Returns:
        A configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        description="A simple, multithreaded TCP port scanner written in pure Python 3.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py -t 127.0.0.1 -p 80\n"
            "  python main.py -t example.com -p 1-1024\n"
            "  python main.py -t 192.168.1.10 -p 22,80,443\n"
            "  python main.py -t 192.168.1.10 -p common --csv results.csv\n\n"
            "DISCLAIMER: Only scan hosts you own or have explicit permission to test."
        ),
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address or hostname to scan (e.g. 192.168.1.1 or example.com).",
    )
    parser.add_argument(
        "-p", "--ports",
        required=True,
        help=(
            "Port(s) to scan. Accepts a single port ('80'), a range ('1-1024'), "
            "a comma-separated list ('22,80,443'), or the keyword 'common' "
            "to scan a curated list of well-known ports."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds for each port connection attempt (default: 1.0).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Maximum number of concurrent scanning threads (default: 100).",
    )
    parser.add_argument(
        "--csv",
        dest="csv_path",
        metavar="FILENAME",
        help="Optional path to export scan results as a CSV file.",
    )

    return parser


def export_to_csv(csv_path: str, target: str, open_ports: list, closed_ports: list,
                   start_time: datetime, end_time: datetime) -> None:
    """
    Export scan results to a CSV file.

    Args:
        csv_path: The file path to write the CSV to.
        target: The scanned target IP address.
        open_ports: A list of (port, service) tuples for open ports.
        closed_ports: A list of port numbers that were closed/filtered.
        start_time: The datetime the scan started.
        end_time: The datetime the scan finished.

    Raises:
        OSError: If the file cannot be written (e.g. permission denied,
                 invalid path).
    """
    with open(csv_path, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)

        # Header / metadata rows.
        writer.writerow(["Target", target])
        writer.writerow(["Scan Start", start_time.strftime("%Y-%m-%d %H:%M:%S")])
        writer.writerow(["Scan End", end_time.strftime("%Y-%m-%d %H:%M:%S")])
        writer.writerow([])

        # Results table.
        writer.writerow(["Port", "Status", "Service"])
        for port, service in open_ports:
            writer.writerow([port, "Open", service])
        for port in closed_ports:
            writer.writerow([port, "Closed", "N/A"])


def print_results(target: str, open_ports: list, closed_ports: list,
                   start_time: datetime, end_time: datetime, duration: float) -> None:
    """
    Print formatted, colored scan results to the terminal.

    Args:
        target: The scanned target IP address.
        open_ports: A list of (port, service) tuples for open ports.
        closed_ports: A list of port numbers that were closed/filtered.
        start_time: The datetime the scan started.
        end_time: The datetime the scan finished.
        duration: Total scan duration in seconds.
    """
    print(f"\n{Colors.CYAN}{Colors.BOLD}Scan Results for {target}{Colors.RESET}")
    print(f"{Colors.CYAN}{'-' * 50}{Colors.RESET}")
    print(f"Scan started : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scan finished: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Duration     : {format_duration(duration)}")
    print(f"{Colors.CYAN}{'-' * 50}{Colors.RESET}\n")

    if open_ports:
        print(f"{Colors.GREEN}{Colors.BOLD}OPEN PORTS ({len(open_ports)}):{Colors.RESET}")
        for port, service in open_ports:
            print(f"  {Colors.GREEN}[OPEN]{Colors.RESET}   Port {port:<6} -> {service}")
    else:
        print(f"{Colors.YELLOW}No open ports found.{Colors.RESET}")

    print()
    print(f"{Colors.RED}{Colors.BOLD}CLOSED PORTS ({len(closed_ports)}):{Colors.RESET}")
    if closed_ports:
        # Closed ports can be numerous (e.g. a full 1-1024 scan), so we
        # print them in a compact, wrapped format rather than one per line.
        closed_str = ", ".join(str(p) for p in closed_ports)
        print(f"  {Colors.RED}{closed_str}{Colors.RESET}")
    else:
        print(f"  {Colors.YELLOW}None{Colors.RESET}")

    print(f"\n{Colors.CYAN}{'-' * 50}{Colors.RESET}")
    print(f"Total ports scanned: {len(open_ports) + len(closed_ports)}")
    print(f"{Colors.CYAN}{'-' * 50}{Colors.RESET}\n")


def main() -> int:
    """
    Main entry point: parses arguments, validates input, runs the scan,
    and displays/exports results.

    Returns:
        An exit code (0 for success, 1 for a handled error).
    """
    print_banner()

    parser = build_arg_parser()
    args = parser.parse_args()

    # --- Validate the target -------------------------------------------- #
    try:
        resolved_target = validate_target(args.target)
    except ValueError as exc:
        print(f"{Colors.RED}[ERROR] {exc}{Colors.RESET}")
        return 1

    # --- Validate/parse the ports ----------------------------------------#
    try:
        ports_to_scan = parse_ports(args.ports)
    except ValueError as exc:
        print(f"{Colors.RED}[ERROR] {exc}{Colors.RESET}")
        return 1

    if not ports_to_scan:
        print(f"{Colors.RED}[ERROR] No valid ports to scan.{Colors.RESET}")
        return 1

    # --- Validate timeout/threads ---------------------------------------#
    if args.timeout <= 0:
        print(f"{Colors.RED}[ERROR] Timeout must be a positive number.{Colors.RESET}")
        return 1

    if args.threads <= 0:
        print(f"{Colors.RED}[ERROR] Thread count must be a positive integer.{Colors.RESET}")
        return 1

    print(f"{Colors.YELLOW}Target resolved to: {resolved_target}{Colors.RESET}")
    print(f"{Colors.YELLOW}Scanning {len(ports_to_scan)} port(s) with "
          f"{args.threads} thread(s)...{Colors.RESET}\n")

    # --- Run the scan ------------------------------------------------------
    scanner = PortScanner(
        target=resolved_target,
        ports=ports_to_scan,
        timeout=args.timeout,
        max_threads=args.threads,
    )

    try:
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[ABORTED] Scan interrupted by user.{Colors.RESET}")
        return 1
    except socket.gaierror:
        print(f"{Colors.RED}[ERROR] Could not resolve target during scan.{Colors.RESET}")
        return 1
    except Exception as exc:  # noqa: BLE001 - top-level safety net for CLI robustness
        print(f"{Colors.RED}[ERROR] An unexpected error occurred: {exc}{Colors.RESET}")
        return 1

    duration = scanner.get_duration()

    # --- Display results -----------------------------------------------#
    print_results(
        target=resolved_target,
        open_ports=scanner.open_ports,
        closed_ports=scanner.closed_ports,
        start_time=scanner.start_time,
        end_time=scanner.end_time,
        duration=duration,
    )

    # --- Optionally export to CSV ---------------------------------------#
    if args.csv_path:
        try:
            export_to_csv(
                csv_path=args.csv_path,
                target=resolved_target,
                open_ports=scanner.open_ports,
                closed_ports=scanner.closed_ports,
                start_time=scanner.start_time,
                end_time=scanner.end_time,
            )
            print(f"{Colors.GREEN}Results exported to: {args.csv_path}{Colors.RESET}")
        except OSError as exc:
            print(f"{Colors.RED}[ERROR] Failed to write CSV file: {exc}{Colors.RESET}")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
