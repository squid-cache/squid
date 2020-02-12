#!/bin/bash
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

if test -z "$1" ; then
	echo "Need squid hostname"
	exit 0
fi
dir=`dirname $0`
if test ! -f $dir/squid.keytab ; then
	echo "Expect $dir/squid.keytab"
	exit 0
fi
# $dir/negotiate_kerberos_auth_test $1 3 | awk '{sub(/Token:/,"YR"); print $0}END{print "QQ"}' | valgrind --log-file=$dir/negotiate_kerberos_auth.val --leak-check=full --show-reachable=yes -v $dir/negotiate_kerberos_auth -d -t none -k squid.keytab
$dir/negotiate_kerberos_auth_test $1 3 | awk '{sub(/Token:/,"YR"); print $0}END{print "QQ"}' | $dir/negotiate_kerberos_auth -d -t none -k $dir/squid.keytab -s GSS_C_NO_NAME
