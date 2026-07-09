"""
SOVP Live Validation Example
Demonstrates full pipeline: DNS TXT resolution + HTTP fetch + Ed25519 verify
against a production SOVP-certified domain.

Protocol specification: draft-litzki-sovp-03
https://datatracker.ietf.org/doc/draft-litzki-sovp/
"""

from sovp.resolver import validate_domain, SOVPResolverError

DOMAIN = "litzki-systems.com"

print(f"SOVP Live Validation — {DOMAIN}")
print("-" * 40)

try:
    result = validate_domain(DOMAIN)
    print(f"Domain:          {result['domain']}")
    print(f"Psi_core:        {result['psi_core']}")
    print(f"Public key ref:  {result['public_key_ref']}")
    print(f"Entity UID:      {result['document']['entity']['uid']}")
    print(f"Canonical URL:   {result['document']['entity']['canonical_url']}")
    print()
    if result["psi_core"] == 1:
        print("Result: VERIFIED — identity and integrity confirmed.")
    else:
        print("Result: FAILED — verification did not pass.")
except SOVPResolverError as e:
    print(f"Resolver error: {e}")
