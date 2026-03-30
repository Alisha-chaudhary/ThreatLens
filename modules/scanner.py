import subprocess
import xml.etree.ElementTree as ET

def run_nmap_scan(target: str) -> dict:
    """
    Runs nmap with service version detection.
    Uses XML output for reliable structured parsing.
    """
    try:
        result = subprocess.run(
            ["nmap", "-sV", "--open", "-oX", "-", target],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode != 0:
            return _error_result("nmap", target, result.stderr)

        return _parse_nmap_xml(result.stdout, target)

    except FileNotFoundError:
        return _error_result("nmap", target, "nmap is not installed or not in PATH")
    except subprocess.TimeoutExpired:
        return _error_result("nmap", target, "nmap scan timed out after 120s")


def _parse_nmap_xml(xml_output: str, target: str) -> dict:
    """Parses nmap XML output into a clean dictionary."""
    ports = []
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            for port in host.findall(".//port"):
                state = port.find("state")
                service = port.find("service")
                if state is not None and state.get("state") == "open":
                    ports.append({
                        "port"    : int(port.get("portid")),
                        "protocol": port.get("protocol"),
                        "service" : service.get("name", "unknown") if service is not None else "unknown",
                        "version" : service.get("version", "")     if service is not None else "",
                        "product" : service.get("product", "")     if service is not None else "",
                    })
    except ET.ParseError as e:
        return _error_result("nmap", target, f"XML parse error: {e}")

    return {
        "tool"       : "nmap",
        "target"     : target,
        "status"     : "success",
        "open_ports" : ports,
        "port_count" : len(ports),
    }


def _error_result(tool: str, target: str, message: str) -> dict:
    """Returns a standard error dict so the rest of the pipeline never crashes."""
    return {
        "tool"      : tool,
        "target"    : target,
        "status"    : "error",
        "error"     : message,
        "open_ports": [],
        "port_count": 0,
    }
