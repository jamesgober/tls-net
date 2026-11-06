"""Fails on any testssl.sh finding of severity HIGH or CRITICAL, except the
certificate-trust findings that come from the test CA (listed below)."""
import json
import sys

# Properties of the test certificate, not of tls-net: it chains to the test
# CA, which no trust store holds; it is valid until 2099, so fixtures never
# expire in CI; and it names no CRL or OCSP responder.
EXPECTED = {
    "cert_chain_of_trust",
    "cert_trust",
    "cert_trust_wildcard",
    "cert_extlifeSpan",
    "cert_revocation",
}
# Printed for the record (docs/SECURITY.md, T-26).
VULNERABILITIES = (
    "heartbleed", "CCS", "ticketbleed", "ROBOT", "secure_renego", "secure_client_renego",
    "CRIME_TLS", "BREACH", "POODLE_SSL", "fallback_SCSV", "SWEET32", "FREAK", "DROWN",
    "LOGJAM", "BEAST", "LUCKY13", "winshock", "RC4", "opossum",
)

findings = json.load(open(sys.argv[1]))
bad = [f for f in findings if f.get("severity") in ("HIGH", "CRITICAL") and f.get("id") not in EXPECTED]
for f in findings:
    if f.get("severity") in ("MEDIUM", "LOW", "HIGH", "CRITICAL"):
        print(f'{f.get("severity"):8} {f.get("id"):40} {f.get("finding")}')
print("
vulnerability checks:")
for f in findings:
    if f.get("id") in VULNERABILITIES or f.get("id", "").startswith(("BEAST", "LOGJAM", "DROWN")):
        print(f'  {f.get("id"):24} {f.get("severity"):8} {f.get("finding")}')
if bad:
    print(f"\n{len(bad)} finding(s) of severity HIGH or CRITICAL:")
    for f in bad:
        print(f'  {f.get("id")}: {f.get("finding")}')
    sys.exit(1)
print("no HIGH or CRITICAL finding beyond the test CA's")
