"""Network utility functions."""

from __future__ import annotations

import ipaddress
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class PortResult:
    """Result of a port scan."""

    host: str
    port: int
    state: str  # open, closed, filtered
    service: str = ""
    banner: str = ""
    version: str = ""


@dataclass
class HostInfo:
    """Information about a discovered host."""

    ip: str
    hostname: str = ""
    os_hint: str = ""
    open_ports: list[PortResult] = field(default_factory=list)
    mac_address: str = ""


COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    464: "kpasswd",
    593: "http-rpc",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3268: "ldap-gc",
    3269: "ldaps-gc",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5985: "winrm-http",
    5986: "winrm-https",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9389: "adws",
}

AD_PORTS = [53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 9389]
DB_PORTS = [1433, 1521, 3306, 5432]
WEB_PORTS = [80, 443, 8080, 8443, 8888]


def expand_targets(targets: list[str]) -> list[str]:
    """Expand CIDR ranges and hostnames to individual IP addresses."""
    expanded: list[str] = []
    for target in targets:
        try:
            network = ipaddress.ip_network(target, strict=False)
            expanded.extend(str(ip) for ip in network.hosts())
        except ValueError:
            expanded.append(target)
    return expanded


def resolve_hostname(hostname: str) -> str | None:
    """Resolve a hostname to an IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def reverse_lookup(ip: str) -> str | None:
    """Reverse DNS lookup for an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def tcp_connect_scan(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 2.0,
    threads: int = 20,
) -> list[PortResult]:
    """Perform a TCP connect scan on the specified host and ports."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    results: list[PortResult] = []

    def _scan_port(port: int) -> PortResult:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                banner = grab_banner(sock, timeout)
                service = COMMON_PORTS.get(port, "unknown")
                return PortResult(
                    host=host,
                    port=port,
                    state="open",
                    service=service,
                    banner=banner,
                )
            sock.close()
            return PortResult(host=host, port=port, state="closed")
        except socket.timeout:
            return PortResult(host=host, port=port, state="filtered")
        except OSError:
            return PortResult(host=host, port=port, state="filtered")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_scan_port, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result.state == "open":
                results.append(result)

    return sorted(results, key=lambda r: r.port)


def grab_banner(sock: socket.socket, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner from an open socket."""
    try:
        sock.settimeout(timeout)
        # Send a generic probe
        sock.send(b"\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        return banner
    except (socket.timeout, OSError, UnicodeDecodeError):
        return ""
    finally:
        try:
            sock.close()
        except OSError:
            pass


def is_host_alive(host: str, timeout: float = 2.0) -> bool:
    """Check if a host is alive via TCP connect to common ports."""
    quick_ports = [445, 139, 135, 80, 443, 22, 88, 389]
    for port in quick_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except OSError:
            continue
    return False


def discover_live_hosts(
    targets: list[str],
    timeout: float = 2.0,
    threads: int = 50,
) -> list[str]:
    """Discover live hosts from a list of targets."""
    ips = expand_targets(targets)
    alive: list[str] = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(is_host_alive, ip, timeout): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                alive.append(ip)

    return sorted(alive, key=lambda x: ipaddress.ip_address(x))
