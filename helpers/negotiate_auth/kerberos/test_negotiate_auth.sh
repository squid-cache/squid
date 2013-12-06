#!/bin/bash
if [[ -z "$1" ]]; then
	echo "Need squid hostname"
	exit 0
fi
dir=`dirname $0`
$dir/negotiate_kerberos_auth_test $1 | awk '{sub(/Token:/,"YR"); print $0}END{print "QQ"}' | $dir/negotiate_kerberos_auth -d
