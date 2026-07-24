"""
scanner.py
----------
Core scanning engine for the Network Port Scanner project.

This module defines the ``PortScanner`` class, which is responsible for:
    * Scanning individual TCP ports using raw sockets
    * Coordinating multithreaded scanning across a list of ports
    * Collecting and storing results (open/closed ports, service names)
    * Tracking scan start time, end time, and total duration

The scanner is intentionally limited to TCP "connect scans" using Python's
built-in ``socket`` module -- no raw sockets or third-party packages (like
scapy) are used, keeping the tool fully cross-platform and dependency-free.
"""

import socket
import threading
from datetime import datetime
from queue import Queue

from utils import get_service_name


class PortScanner:
    """
    A simple, multithreaded TCP port scanner.

    Attributes:
        target (str): The resolved IP address to scan.
        ports (list): The list of port numbers to scan.
        timeout (float): The socket connection timeout, in seconds.
        max_threads (int): The maximum number of worker threads to use.
        open_ports (list): Populated after scanning -- list of (port, service) tuples.
        closed_ports (list): Populated after scanning -- list of port numbers.
        start_time (datetime): Timestamp for when the scan began.
        end_time (datetime): Timestamp for when the scan finished.
    """

    def __init__(self, target: str, ports: list, timeout: float = 1.0, max_threads: int = 100):
        """
        Initialize the PortScanner.

        Args:
            target: The IP address to scan (already resolved/validated).
            ports: A list of port numbers to scan.
            timeout: How long (in seconds) to wait for a connection attempt
                     before considering the port closed/filtered.
            max_threads: The maximum number of concurrent scanning threads.
        """
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.max_threads = max_threads

        # Results are shared across threads, so we protect them with a lock.
        self.open_ports = []
        self.closed_ports = []
        self._lock = threading.Lock()

        self.start_time = None
        self.end_time = None

    def _scan_port(self, port: int) -> None:
        """
        Attempt to open a TCP connection to a single port on the target.

        This is the worker function executed by each thread. It creates a
        new socket, tries to connect, and records the result (open or
        closed) in a thread-safe manner.

        Args:
            port: The port number to scan.
        """
        # A new socket is created per-port/per-thread to avoid sharing
        # socket state across threads, which is not safe.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            # connect_ex returns 0 on success instead of raising an exception,
            # which makes it convenient for scanning (no try/except needed
            # just to detect a refused connection).
            result = sock.connect_ex((self.target, port))

            if result == 0:
                service = get_service_name(port)
                with self._lock:
                    self.open_ports.append((port, service))
            else:
                with self._lock:
                    self.closed_ports.append(port)

        except socket.timeout:
            # Treat a timeout the same as a closed/filtered port.
            with self._lock:
                self.closed_ports.append(port)

        except OSError:
            # Covers unreachable host, network errors, etc. for this
            # specific port -- we don't want one bad port to crash the
            # whole scan, so we record it as closed and move on.
            with self._lock:
                self.closed_ports.append(port)

        finally:
            sock.close()

    def _worker(self, queue: Queue) -> None:
        """
        Worker loop for a scanning thread: pulls ports from the queue and
        scans them until the queue is empty.

        Args:
            queue: A thread-safe Queue containing port numbers to scan.
        """
        while True:
            try:
                port = queue.get_nowait()
            except Exception:
                # Queue is empty -- this thread's work is done.
                break

            self._scan_port(port)
            queue.task_done()

    def run(self) -> None:
        """
        Execute the port scan using a pool of worker threads.

        Populates ``self.open_ports``, ``self.closed_ports``,
        ``self.start_time``, and ``self.end_time``.
        """
        self.start_time = datetime.now()

        # Build a thread-safe queue of ports to scan.
        port_queue = Queue()
        for port in self.ports:
            port_queue.put(port)

        # Don't spin up more threads than there are ports to scan.
        thread_count = min(self.max_threads, len(self.ports)) or 1

        threads = []
        for _ in range(thread_count):
            thread = threading.Thread(target=self._worker, args=(port_queue,), daemon=True)
            threads.append(thread)
            thread.start()

        # Wait for all threads to finish processing the queue.
        for thread in threads:
            thread.join()

        self.end_time = datetime.now()

        # Sort results for consistent, readable output.
        self.open_ports.sort(key=lambda item: item[0])
        self.closed_ports.sort()

    def get_duration(self) -> float:
        """
        Calculate the total scan duration in seconds.

        Returns:
            The duration in seconds as a float. Returns 0.0 if the scan
            has not been run yet.
        """
        if self.start_time is None or self.end_time is None:
            return 0.0
        return (self.end_time - self.start_time).total_seconds()
