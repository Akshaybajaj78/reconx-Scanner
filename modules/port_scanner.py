import nmap
from urllib.parse import urlparse


def _extract_host(target: str) -> str:
    parsed = urlparse(target)
    host = parsed.netloc if parsed.netloc else target
    return host.split(":")[0]


def scan_top_ports(target: str, host_timeout: str = "30s"):
    """
    Scan top 1000 TCP ports using nmap.
    Returns a list of open ports like ["80/tcp", "443/tcp"].
    """
    open_ports = []
    try:
        host = _extract_host(target)
        scanner = nmap.PortScanner()
        # TCP connect scan to avoid requiring root privileges
        # -Pn skips host discovery to handle hosts that drop ping
        scanner.scan(host, arguments=f"--top-ports 1000 -sT -T4 -Pn --host-timeout {host_timeout}")

        if host not in scanner.all_hosts():
            return open_ports

        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                state = scanner[host][proto][port].get("state")
                if state == "open":
                    open_ports.append(f"{port}/{proto}")
    except Exception:
        # Keep errors silent to avoid breaking overall scan flow
        return open_ports

    return open_ports
