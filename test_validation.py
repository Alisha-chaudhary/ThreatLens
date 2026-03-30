from utils.validation import validate_input, sanitise_target

tests = [
    "example.com",
    "https://example.com/",
    "192.168.1.1",
    "999.999.999.999",
    "not_a_domain",
    "evil.com; rm -rf /",      # shell injection attempt
    "sub.domain.co.uk",
]

for t in tests:
    result = validate_input(t)
    clean  = sanitise_target(t)
    print(f"Input: {t!r:35} → Type: {str(result):8} | Sanitised: {clean!r}")
