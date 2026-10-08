#!/bin/sh
# gen_starttls_fixtures.sh - the ECDSA half of an RSA + ECDSA pair for the CLI's --tls-audit tests
# (tests/python/test_starttls_audit.py): starttls_ec_leaf.pem, a self-signed EC P-256 certificate
# for www.example.com and example.com (the names of the RSA bundle_leaf.pem), and its throwaway
# key starttls_ec_leaf.key. Dev tool, needs OpenSSL 3; run from tests/fixtures.
set -eu
openssl ecparam -name prime256v1 -genkey -noout -out starttls_ec_leaf.key
openssl req -new -x509 -key starttls_ec_leaf.key -subj '/CN=www.example.com' -sha256 \
  -days 9000 -set_serial 0x5701 \
  -addext 'subjectAltName=DNS:www.example.com,DNS:example.com' \
  -addext 'keyUsage=critical,digitalSignature' -addext 'extendedKeyUsage=serverAuth' \
  -out starttls_ec_leaf.pem
