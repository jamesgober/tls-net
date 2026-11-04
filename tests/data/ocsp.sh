#!/usr/bin/env bash
# OCSP responses for site.pem, signed by the intermediate: good, and revoked.
# Run from tests/data after generate.sh. Test material only.
set -euo pipefail
cd "$(dirname "$0")"
SERIAL=$(openssl x509 -in site.pem -noout -serial | cut -d= -f2)
openssl x509 -in site.pem -out site.leaf.crt
openssl ocsp -issuer inter.pem -cert site.leaf.crt -no_nonce -reqout ocsp.req
printf 'V\t991231235959Z\t\t%s\tunknown\t/CN=site\n' "$SERIAL" > index.txt
openssl ocsp -index index.txt -rsigner inter.pem -rkey inter.key -CA inter.pem -reqin ocsp.req -respout site.ocsp -ndays 27000
printf 'R\t991231235959Z\t260201000000Z\t%s\tunknown\t/CN=site\n' "$SERIAL" > index.txt
openssl ocsp -index index.txt -rsigner inter.pem -rkey inter.key -CA inter.pem -reqin ocsp.req -respout site.revoked.ocsp -ndays 27000
rm -f index.txt index.txt.attr ocsp.req site.leaf.crt
