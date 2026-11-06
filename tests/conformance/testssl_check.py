"""Fails on any testssl.sh finding of severity HIGH or CRITICAL, except the
certificate-trust findings that come from the test CA (listed below)."""
import json
import sys

# The test certificate chains to tls-net's test CA, which no trust store
# holds, and names localhost; these findings say exactly that.
EXPECTED = {
    "cert_chain_of_trust",
    "cert_trust",
    "cert_trust_wildcard",
}

findings = json.load(open(sys.argv[1]))
bad = [f for f in findings if f.get("severity") in ("HIGH", "CRITICAL") and f.get("id") not in EXPECTED]
for f in findings:
    if f.get("severity") in ("MEDIUM", "LOW", "HIGH", "CRITICAL"):
        print(f'{f.get("severity"):8} {f.get("id"):40} {f.get("finding")}')
if bad:
    print(f"\n{len(bad)} finding(s) of severity HIGH or CRITICAL:")
    for f in bad:
        print(f'  {f.get("id")}: {f.get("finding")}')
    sys.exit(1)
print("no HIGH or CRITICAL finding beyond the test CA's")
