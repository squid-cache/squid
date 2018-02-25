#!/bin/sh

#
# test certificates and keys
#

CERTTOOL="$1"
OPENSSL="$2"

if test "x$CERTTOOL" != "x" -a -x $CERTTOOL; then

	#
	# self-signed root CA
	#
	echo "
		organization = \"Example.Org\"
		cn = \"Test CA. Do not Trust\"
		dc = \"example.org\"
		expiration_days = 365
		ca
		cert_signing_key
		crl_signing_key
		tls_www_server
		" > example.org-ca

	$CERTTOOL --generate-privkey --rsa --outfile ca-root-rsa.pkey

	$CERTTOOL --generate-self-signed --template example.org-ca \
		--rsa --load-privkey ca-root-rsa.pkey --outfile ca-root-rsa.crt

	rm example.org-ca

	#
	# intermediary CA, signed by root
	#
	echo "
	organization = \"Example.Net\"
	cn = \"Test CA. Do not Trust\"
	dc = \"example.net\"
	expiration_days = 365
	ca
	cert_signing_key
	crl_signing_key
	tls_www_server
	" > example.net-ca

	$CERTTOOL --generate-privkey --rsa --outfile ca-mid-rsa.pkey

	$CERTTOOL --generate-certificate --load-privkey ca-mid-rsa.pkey \
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
	expiration_days = 365
	tls_www_server
	" >example.com-leaf

	$CERTTOOL --generate-privkey --rsa --outfile leaf-rsa.pkey

	$CERTTOOL --generate-certificate --load-privkey leaf-rsa.pkey \
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

elif test "x$OPENSSL" != "x" -a -x $OPENSSL; then

	# TODO: generate certificates with openssl's tool
	echo "ERROR: still missing OpenSSL certificate creation"
	exit 1

else
	echo "ERROR: cannot find a tool to generate certificates"
	exit 1
fi
