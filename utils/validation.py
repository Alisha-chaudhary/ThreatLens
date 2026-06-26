# utils/validation.py
import re

def validate_input(target: str) -> Literal["ip", "domain"] | None:
    """
    Accepts a raw string from the user.
    Returns 'domain', 'ip', or None if invalid.
    """
    target = target.strip().lower()

    # Remove protocol prefixes if user types https://example.com
    target = re.sub(r'^https?://', '', target)
    # Remove trailing slashes
    target = target.rstrip('/')

    if _is_ip(target):
        return 'ip'
    elif _is_domain(target):
        return 'domain'
    else:
        return None


def sanitise_target(target: str) -> str:
    """
    Cleans the target string for safe use in subprocess calls.
    Removes characters that could be used for shell injection.
    """
    target = target.strip().lower()
    target = re.sub(r'^https?://', '', target)
    target = target.rstrip('/')
    # Only allow alphanumeric, dots, hyphens (safe for domain/IP)
    target = re.sub(r'[^a-z0-9.\-]', '', target)
    return target


def _is_ip(value: str) -> bool:
    """Checks if the value is a valid IPv4 address."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, value):
        parts = value.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    return False


def _is_domain(value: str) -> bool:
    """Checks if the value is a valid domain name."""
    pattern = r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    return bool(re.match(pattern, value))
