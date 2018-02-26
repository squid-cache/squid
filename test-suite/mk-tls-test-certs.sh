#!/bin/sh

#
# test certificates and keys
#

CERTTOOL="$1"
OPENSSL="$2"

if test "x$OPENSSL" != "x" -a -x $OPENSSL; then

	#
	# self-signed root CA
	#
	echo "
		[ ca ]
		default_ca= test_CA
		[ test_CA ]
		default_days= 365
		default_md= sha256
		preserve= no
		[ req ]
		distinguished_name= root_ca_distinguished_name
		prompt= no
		x509_extensions= root_ca_extensions
		[ root_ca_distinguished_name ]
		organizationName= Example.Org
		commonName= Test CA. Do not Trust
		[ root_ca_extensions ]
		basicConstraints = CA:true
	" > example.org-ca || exit $?

	openssl req --verbose --newkey rsa:2048 --x509 --nodes --set_serial 1 \
		--config example.org-ca \
		--keyout ca-root-rsa.pkey.tmp \
		--out ca-root-rsa.crt || exit $?

	openssl rsa --in ca-root-rsa.pkey.tmp --out ca-root-rsa.pkey || exit $?

	rm -f ca-root-rsa.pkey.tmp example.org-ca || exit $?

	#
	# intermediary CA, signed by root
	#
	echo "
		[ ca ]
		default_ca= test_CA
		[ test_CA ]
		default_md= sha256
		preserve= no
		[ req ]
		distinguished_name= root_ca_distinguished_name
		prompt= no
		x509_extensions= root_ca_extensions
		[ root_ca_distinguished_name ]
		organizationName= Example.Net
		commonName= Test CA. Do not Trust
		[ root_ca_extensions ]
		basicConstraints= CA:true
	" > example.net-ca || exit $?

	openssl genrsa --out ca-mid-rsa.pkey.tmp 4096 || exit $?

	openssl req --new --sha256 --set_serial 2 \
		--config example.net-ca \
		--key ca-mid-rsa.pkey.tmp \
		--out ca-mid-rsa.csr || exit $?

	openssl rsa --in ca-mid-rsa.pkey.tmp --out ca-mid-rsa.pkey || exit $?

	# CA signs Intermediate
	openssl x509 --req --days 365 \
		--in ca-mid-rsa.csr \
		--CA ca-root-rsa.crt --CAkey ca-root-rsa.pkey --set_serial 2 \
		--out ca-mid-rsa.crt || exit $?

	rm -f ca-mid-rsa.csr ca-mid-rsa.pkey.tmp example.net-ca || exit $?

	#
	# Standard leaf / non-CA certificate
	#
	echo "
		[ ca ]
		default_ca= test_CA
		[ test_CA ]
		default_md= sha1
		preserve= no
		[ req ]
		distinguished_name= user_distinguished_name
		prompt= no
		x509_extensions= user_extensions
		[ user_distinguished_name ]
		organizationName= Example.Com
		commonName= Test CA. Do not Trust
		[ user_extensions ]
		basicConstraints= CA:false
	" >example.com-leaf || exit $?

	openssl genrsa --out leaf-rsa.pkey.tmp 4096 || exit $?

	openssl req --new --sha256 --set_serial 3 \
		--config example.com-leaf \
		--key leaf-rsa.pkey.tmp \
		--out leaf-rsa.csr || exit $?

	openssl rsa --in leaf-rsa.pkey.tmp --out leaf-rsa.pkey || exit $?

	openssl x509 --req --days 365 \
		--in leaf-rsa.csr \
		--CA ca-root-rsa.crt --CAkey ca-root-rsa.pkey --set_serial 3 \
		--out leaf-rsa.crt || exit $?

	rm -f leaf-rsa.csr leaf-rsa.pkey.tmp example.com-leaf || exit $?

	#
	# PEM files with CA chain
	#
	cat ca-root-rsa.pkey ca-root-rsa.crt > ca-root-rsa.pem || exit $?
	cat ca-mid-rsa.pkey ca-mid-rsa.crt > ca-mid-rsa.pem || exit $?
	cat ca-mid-rsa.pkey ca-mid-rsa.crt ca-root-rsa.crt > ca-chain-rsa.pem || exit $?
	cat leaf-rsa.pkey leaf-rsa.crt ca-root-rsa.crt > leaf-chain-rsa.pem || exit $?

elif test "x$CERTTOOL" != "x" -a -x $CERTTOOL; then

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
		" > example.org-ca || exit $?

	$CERTTOOL --generate-privkey --rsa --outfile ca-root-rsa.pkey || exit $?

	$CERTTOOL --generate-self-signed --template example.org-ca \
		--rsa --load-privkey ca-root-rsa.pkey --outfile ca-root-rsa.crt || exit $?

	rm example.org-ca || exit $?

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
	" > example.net-ca || exit $?

	$CERTTOOL --generate-privkey --rsa --outfile ca-mid-rsa.pkey || exit $?

	$CERTTOOL --generate-certificate --load-privkey ca-mid-rsa.pkey \
		--load-ca-certificate ca-root-rsa.crt --load-ca-privkey ca-root-rsa.pkey \
		--template example.net-ca --outfile ca-mid-rsa.crt || exit $?

	rm example.net-ca || exit $?

	#
	# Standard leaf / non-CA certificate
	#
	echo "
	organization = \"Example.Com\"
	cn = \"Test CA. Do not Trust\"
	dc = \"example.com\"
	expiration_days = 365
	tls_www_server
	" >example.com-leaf || exit $?

	$CERTTOOL --generate-privkey --rsa --outfile leaf-rsa.pkey || exit $?

	$CERTTOOL --generate-certificate --load-privkey leaf-rsa.pkey \
		--load-ca-certificate ca-root-rsa.crt --load-ca-privkey ca-root-rsa.pkey \
		--template example.com-leaf --outfile leaf-rsa.crt || exit $?

	rm -f example.com-leaf || exit $?

	#
	# PEM files with CA chain
	#
	cat ca-root-rsa.pkey ca-root-rsa.crt > ca-root-rsa.pem || exit $?
	cat ca-mid-rsa.pkey ca-mid-rsa.crt > ca-mid-rsa.pem || exit $?
	cat ca-mid-rsa.pkey ca-mid-rsa.crt ca-root-rsa.crt > ca-chain-rsa.pem || exit $?
	cat leaf-rsa.pkey leaf-rsa.crt ca-root-rsa.crt > leaf-chain-rsa.pem || exit $?

else
	echo "WARNING: cannot find a tool to generate certificates"
fi
