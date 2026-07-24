"""
utils.py
--------
Utility functions and constants for the Network Port Scanner project.

This module contains:
    * ANSI color codes for terminal output (no third-party libraries required)
    * Input validation helpers (IP address / hostname / port parsing)
    * A small dictionary of common ports mapped to their well-known service names
    * A helper to resolve a hostname to an IP address

Keeping these helpers in a separate module keeps ``scanner.py`` and
``main.py`` focused on their core responsibilities (scanning and CLI
orchestration respectively).
"""

import socket
import ipaddress


# --------------------------------------------------------------------------- #
# ANSI color codes
# --------------------------------------------------------------------------- #
# These escape codes work in most modern terminals (Linux, macOS, and
# Windows 10+ terminals). No third-party library (e.g. colorama) is used,
# per the project requirements.
class Colors:
    """Container for ANSI escape codes used to color terminal output."""

    GREEN = "\033[92m"     # Open ports
    RED = "\033[91m"       # Closed ports / errors
    YELLOW = "\033[93m"    # Warnings / info
    CYAN = "\033[96m"      # Headers / titles
    BOLD = "\033[1m"       # Bold text
    RESET = "\033[0m"      # Reset to default terminal color


# --------------------------------------------------------------------------- #
# Common ports and their associated service names
# --------------------------------------------------------------------------- #
# This is not an exhaustive list -- it covers the most frequently scanned
# "well-known" ports. It is used for both the "common ports" scan mode and
# for displaying a friendly service name next to each open port.
COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBIND",
    135: "MSRPC",
    139: "NETBIOS-SSN",
    143: "IMAP",
    443: "HTTPS",
    445: "MICROSOFT-DS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1723: "PPTP",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-PROXY",
    8443: "HTTPS-ALT",
}


def get_service_name(port: int) -> str:
    """
    Return a human-readable service name for a given port number.

    Tries the local COMMON_PORTS dictionary first (fast, no network calls),
    then falls back to Python's built-in ``socket.getservbyport`` which uses
    the operating system's service database. If neither source knows the
    port, "Unknown" is returned.

    Args:
        port: The port number to look up.

    Returns:
        A string containing the service name, or "Unknown" if not found.
    """
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]

    try:
        return socket.getservbyport(port).upper()
    except (OSError, socket.error):
        return "Unknown"


def validate_target(target: str) -> str:
    """
    Validate and resolve a target (IP address or hostname) to an IP address.

    Args:
        target: A string containing an IP address or a hostname
                (e.g. "192.168.1.1" or "example.com").

    Returns:
        The resolved IP address as a string.

    Raises:
        ValueError: If the target is empty, cannot be resolved, or is
                    otherwise invalid.
    """
    if not target or not target.strip():
        raise ValueError("Target cannot be empty.")

    target = target.strip()

    # First, check if the target is already a valid IP address.
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        # Not a raw IP address -- try to resolve it as a hostname.
        pass

    try:
        resolved_ip = socket.gethostbyname(target)
        return resolved_ip
    except socket.gaierror as exc:
        raise ValueError(
            f"Unable to resolve hostname '{target}'. "
            f"Please check the spelling or your network connection."
        ) from exc


def parse_ports(port_arg: str) -> list:
    """
    Parse a port specification string into a sorted list of unique ports.

    Supported formats:
        * Single port:      "80"
        * Port range:       "1-1024"
        * Comma-separated:  "22,80,443"
        * Mixed:            "22,80,1000-1010"
        * Keyword "common":  returns the ports defined in COMMON_PORTS

    Args:
        port_arg: The raw port argument string supplied by the user.

    Returns:
        A sorted list of unique, valid port numbers (1-65535).

    Raises:
        ValueError: If the format is invalid, ports are out of range,
                    or a range is malformed (e.g. start > end).
    """
    if not port_arg or not port_arg.strip():
        raise ValueError("Port specification cannot be empty.")

    port_arg = port_arg.strip().lower()

    # Special keyword: scan the built-in list of common ports.
    if port_arg == "common":
        return sorted(COMMON_PORTS.keys())

    ports = set()

    # Split on commas to support mixed single ports and ranges.
    segments = [seg.strip() for seg in port_arg.split(",") if seg.strip()]
    if not segments:
        raise ValueError("Port specification cannot be empty.")

    for segment in segments:
        if "-" in segment:
            # Handle a port range, e.g. "1000-1010"
            parts = segment.split("-")
            if len(parts) != 2:
                raise ValueError(f"Invalid port range format: '{segment}'.")

            start_str, end_str = parts[0].strip(), parts[1].strip()
            if not start_str.isdigit() or not end_str.isdigit():
                raise ValueError(f"Port range must contain numbers only: '{segment}'.")

            start, end = int(start_str), int(end_str)
            _validate_port_number(start)
            _validate_port_number(end)

            if start > end:
                raise ValueError(
                    f"Invalid port range '{segment}': start port must be "
                    f"less than or equal to end port."
                )
            ports.update(range(start, end + 1))
        else:
            # Handle a single port, e.g. "80"
            if not segment.isdigit():
                raise ValueError(f"Invalid port number: '{segment}'.")
            port = int(segment)
            _validate_port_number(port)
            ports.add(port)

    return sorted(ports)


def _validate_port_number(port: int) -> None:
    """
    Ensure a port number falls within the valid TCP/UDP port range.

    Args:
        port: The port number to validate.

    Raises:
        ValueError: If the port is outside the 1-65535 range.
    """
    if port < 1 or port > 65535:
        raise ValueError(f"Port {port} is out of valid range (1-65535).")


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds into a human-readable string.

    Args:
        seconds: The duration in seconds (may include a fractional part).

    Returns:
        A formatted string, e.g. "2.35 seconds".
    """
    return f"{seconds:.2f} seconds"
