#!/usr/bin/env bash
# CRLs from the test intermediate, and a self-signed server certificate, for
# the T-6 attack tests. Test material only. Run after generate.sh (it needs
# inter.pem, inter.key, and site.pem).
set -euo pipefail
cd "$(dirname "$0")"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cat > "$W/ca.cnf" <<CNF
[ca]
default_ca = test
[test]
database = $W/index.txt
crlnumber = $W/crlnumber
default_md = sha256
default_crl_days = 27000
crl_extensions = crl_ext
[crl_ext]
authorityKeyIdentifier = keyid:always
CNF
: > "$W/index.txt"
echo 01 > "$W/crlnumber"
# An empty CRL, then one that lists site.pem's serial.
openssl ca -config "$W/ca.cnf" -gencrl -cert inter.pem -keyfile inter.key -out inter-empty.crl.pem
openssl x509 -in site.pem -out "$W/site.crt"
openssl ca -config "$W/ca.cnf" -revoke "$W/site.crt" -cert inter.pem -keyfile inter.key
openssl ca -config "$W/ca.cnf" -gencrl -cert inter.pem -keyfile inter.key -out inter-revokes-site.crl.pem
# Self-signed, for a name the client asks for: no chain to any anchor.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout selfsigned.key \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" -addext "basicConstraints=critical,CA:FALSE"   -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=serverAuth" -days 27000 -out selfsigned.pem
