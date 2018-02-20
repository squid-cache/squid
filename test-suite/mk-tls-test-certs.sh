#!/bin/sh

#
# test certificates and keys
#

if test -x /usr/bin/certtool; then

echo "
organization = \"Example.Org\"
cn = \"Test CA. Do not Trust\"
dc = \"example.org\"
expiration_days = 700
ca
cert_signing_key
crl_signing_key
tls_www_server
" >example.org-ca

#
# self-signed root CA
#
/usr/bin/certtool --generate-privkey --rsa --outfile ca-root-rsa.pkey

/usr/bin/certtool --generate-self-signed --template example.org-ca \
	--rsa --load-privkey ca-root-rsa.pkey --outfile ca-root-rsa.crt

rm example.org-ca

#
# intermediary CA, signed by root
#
echo "
organization = \"Example.Net\"
cn = \"Test CA. Do not Trust\"
dc = \"example.net\"
expiration_days = 700
ca
cert_signing_key
crl_signing_key
tls_www_server
" >example.net-ca

/usr/bin/certtool --generate-privkey --rsa --outfile ca-mid-rsa.pkey

/usr/bin/certtool --generate-certificate --load-privkey ca-mid-rsa.pkey \
	--load-ca-certificate ca-root-rsa.crt --load-ca-privkey ca-root-rsa.pkey \
	--template example.net-ca --outfile ca-mid-rsa.crt

rm example.net-ca

#
# Standard leaf / non-CA certificate
#

echo "
organization = \"Example.Com\"
cn = \"Test CA. Do not Trust\"
dc = \"example.com\"
expiration_days = 700
tls_www_server
" >example.com-leaf

/usr/bin/certtool --generate-privkey --rsa --outfile leaf-rsa.pkey

/usr/bin/certtool --generate-certificate --load-privkey leaf-rsa.pkey \
	--load-ca-certificate ca-root-rsa.crt --load-ca-privkey ca-root-rsa.pkey \
	--template example.com-leaf --outfile leaf-rsa.crt

rm example.com-leaf

#
# PEM files with CA chain
#
cat ca-root-rsa.crt ca-root-rsa.pkey >ca-root-rsa.pem
cat ca-mid-rsa.crt ca-mid-rsa.pkey >ca-mid-rsa.pem
cat ca-mid-rsa.crt ca-mid-rsa.pkey ca-root-rsa.crt >ca-chain-rsa.pem
cat leaf-rsa.crt leaf-rsa.pkey ca-root-rsa.crt >leaf-chain-rsa.pem


else
    echo "ERROR: canont find /usr/bin/certtool"
fi
