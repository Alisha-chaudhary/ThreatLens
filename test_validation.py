from utils.validation import validate_input, sanitise_target


def test_valid_domain():
    assert validate_input("example.com") == "domain"


def test_https_domain():
    assert validate_input("https://example.com/") == "domain"


def test_valid_ip():
    assert validate_input("192.168.1.1") == "ip"


def test_invalid_ip():
    assert validate_input("999.999.999.999") is None


def test_invalid_domain():
    assert validate_input("not_a_domain") is None


def test_shell_injection_input():
    assert validate_input("evil.com; rm -rf /") is None
    assert sanitise_target("evil.com; rm -rf /") == "evil.comrm-rf"


def test_subdomain():
    assert validate_input("sub.domain.co.uk") == "domain"


def test_sanitise_https_domain():
    assert sanitise_target("https://example.com/") == "example.com"
