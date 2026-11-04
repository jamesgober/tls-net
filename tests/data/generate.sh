#!/usr/bin/env bash
# Regenerates the test certificates and keys in this directory.
# Test material only: none of these keys protects anything.
# Needs OpenSSL 3.4 or later (for -not_before and -not_after).
set -euo pipefail
cd "$(dirname "$0")"
FROM=20260101000000Z
TO=20991231235959Z

ext() { # name, SANs, EKU, extra
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n%s%s%s\n' \
    "${2:+subjectAltName=$2
}" "${3:+extendedKeyUsage=$3
}" "${4:-}" > "$1.ext"
}
ca_ext() { printf 'basicConstraints=critical,CA:TRUE%s\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' "${1:-}" > ca.ext; }

# Root and intermediate CAs (ECDSA P-256).
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
ca_ext
openssl req -new -key ca.key -subj "/CN=tls-net test root" -out ca.csr
openssl x509 -req -in ca.csr -signkey ca.key -sha256 -not_before $FROM -not_after $TO -extfile ca.ext -out ca.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter.key
ca_ext ",pathlen:0"
openssl req -new -key inter.key -subj "/CN=tls-net test intermediate" -out inter.csr
openssl x509 -req -in inter.csr -CA ca.pem -CAkey ca.key -sha256 -not_before $FROM -not_after $TO -extfile ca.ext -set_serial 2 -out inter.pem

leaf() { # name, keygen args, SANs, EKU, sigalg, from, to, issuer
  local name=$1 keyargs=$2 sans=$3 eku=$4 sig=${5:--sha256} from=${6:-$FROM} to=${7:-$TO} issuer=${8:-inter}
  openssl genpkey $keyargs -out "$name.key"
  openssl req -new -key "$name.key" -subj "/CN=$name" -out "$name.csr"
  ext "$name" "$sans" "$eku"
  openssl x509 -req -in "$name.csr" -CA "$issuer.pem" -CAkey "$issuer.key" $sig -not_before $from -not_after $to \
    -extfile "$name.ext" -set_serial "0x$(openssl rand -hex 8)" -out "$name.crt"
  cat "$name.crt" "$issuer.pem" > "$name.pem"
  rm -f "$name.csr" "$name.ext" "$name.crt"
}
P256="-algorithm EC -pkeyopt ec_paramgen_curve:P-256"
SITE="DNS:localhost,DNS:example.test,DNS:*.example.test,IP:127.0.0.1"

leaf site "$P256" "$SITE" serverAuth
leaf api "$P256" "DNS:api.other.test" serverAuth
leaf site-rsa "-algorithm RSA -pkeyopt rsa_keygen_bits:2048" "$SITE" serverAuth
leaf ed25519 "-algorithm ED25519" "DNS:localhost" serverAuth ""
leaf p384 "-algorithm EC -pkeyopt ec_paramgen_curve:P-384" "DNS:localhost" serverAuth -sha384
leaf p521 "-algorithm EC -pkeyopt ec_paramgen_curve:P-521" "DNS:localhost" serverAuth -sha512
leaf rsa1024 "-algorithm RSA -pkeyopt rsa_keygen_bits:1024" "DNS:localhost" serverAuth
leaf sha1 "$P256" "DNS:localhost" serverAuth -sha1
leaf expired "$P256" "DNS:localhost" serverAuth -sha256 20200101000000Z 20210101000000Z
leaf future "$P256" "DNS:localhost" serverAuth -sha256 20900101000000Z $TO
leaf client-only "$P256" "DNS:localhost" clientAuth
leaf no-eku "$P256" "DNS:localhost" ""
leaf no-san "$P256" "" serverAuth
leaf client "$P256" "DNS:client.test,URI:spiffe://test/client" clientAuth
# A certificate of about 12 KiB (400 names), for handshake budget tests.
BIG="DNS:localhost$(for i in $(seq 1 400); do printf ',DNS:host-%03d.big.test' "$i"; done)"
leaf big "$P256" "$BIG" serverAuth

# Key forms for intake tests.
openssl pkey -in site-rsa.key -traditional -out site-rsa.pkcs1.key
openssl pkey -in site.key -traditional -out site.sec1.key
openssl pkcs8 -topk8 -in site.key -passout pass:test -out site.encrypted.key
openssl pkcs8 -topk8 -nocrypt -in site.key -outform DER -out site.key.der
# A chain in the wrong order (intermediate first).
openssl x509 -in site.pem -out site.leaf.crt
cat inter.pem site.leaf.crt > site.reversed.pem
rm -f site.leaf.crt ca.csr inter.csr ca.ext ca.srl inter.srl
