# Security Policy

We take security seriously. ThreatLens maintains high standards for code integrity, user safety, responsible data handling, and coordinated vulnerability disclosure.

---

## Reporting Vulnerabilities

Discovered a vulnerability? Please report it responsibly.

**Email:** [bluxbxllalisha@gmail.com]  
**Response time:** Within 24 hours

### Do This
- Email security details privately
- Include: description, impact, proof of concept
- Allow 30 days for patch development
- Wait for release before public disclosure

### Don't Do This
- Post in public GitHub issues
- Share on social media
- Attempt exploitation
- Sell vulnerability information

### Timeline
```
Day 1:   Report received
Day 3:   Initial response from security team
Day 7:   Analysis complete, patch development started
Day 14:  Patch ready for testing
Day 30:  Patch released, vulnerability disclosed with credit
```

---

## Security Practices

### Input Validation
All user input validated against whitelist patterns to prevent shell injection:

```python
import re
DANGEROUS_CHARS = r'[;&|`$><\(\)\[\]{}\'"\\]'

def validate_target(target: str) -> bool:
    if re.search(DANGEROUS_CHARS, target):
        raise ValueError("Invalid target format")
    return True
```

### Subprocess Execution
```python
# ✅ CORRECT: Array-based execution
subprocess.run(['nmap', '-A', target], capture_output=True)

# ❌ DANGEROUS: Shell interpolation
subprocess.run(f'nmap {target}', shell=True)
```

### Secrets Management
- API keys loaded from environment variables
- Never hardcoded or committed to repository
- Rotated regularly per security best practices

### Rate Limiting & Politeness
- DNS queries cached to minimize requests
- HTTP requests include proper User-Agent headers and timeouts
- NVD API respects rate limits with exponential backoff
- External tools respect built-in rate limiting

### Network Safety
- All operations have timeouts to prevent resource exhaustion
- Error handling never exposes system paths, credentials, or internals
- Safe defaults applied across all modules

### Dependency Management
Dependencies actively maintained and regularly audited:
- requests: 2.31.0+
- dnspython: 2.4.0+
- reportlab: 4.0.0+
- jinja2: 3.1.0+

---

## Legal Compliance

### Authorized Use Only

**Permitted:**
- Systems you own or manage
- Authorized penetration tests (with signed contract)
- Academic learning with permission
- Compliance assessments

**Not Permitted:**
- Unauthorized scanning
- Exceeding agreed scope
- Testing competitors' infrastructure
- Any activity without explicit written consent

### Applicable Laws

- **USA:** Computer Fraud and Abuse Act (18 U.S.C. § 1030)  
  Penalties: up to 10 years, $250,000

- **UK:** Computer Misuse Act 1990  
  Unauthorized access: 2-10 years imprisonment

- **EU:** GDPR & ePrivacy Directive  
  Penalties: €20M or 4% global revenue

- **India:** IT Act 2000  
  Unauthorized access: 3 years, ₹500,000

- **Australia:** Criminal Code 1995  
  Unauthorized access: up to 10 years imprisonment

---

## Before Scanning

Verify all of the following:

- [ ] Explicit written authorization obtained
- [ ] Scope clearly defined (which systems, what tests)
- [ ] Testing window specified (dates and times)
- [ ] Emergency contact information available
- [ ] You understand your jurisdiction's laws
- [ ] Incident response procedures understood

---

## Key Principles

1. **Respect Privacy** — Collect only necessary data
2. **Be Honest** — Report findings accurately  
3. **Do No Harm** — Don't disrupt services or escalate access
4. **Respect Autonomy** — Only test authorized systems
5. **Act Professionally** — Timely reporting, strict confidentiality

---

## Contact

**Security issues:** [bluxbxllalisha@gmail.com]  
**Other issues:** GitHub Issues or Discussions tab

---

**Last Updated: May 2025**
