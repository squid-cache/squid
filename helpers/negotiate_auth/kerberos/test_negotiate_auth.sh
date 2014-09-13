#!/bin/bash
#
## Copyright (C) 1996-2014 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

if [[ -z "$1" ]]; then
	echo "Need squid hostname"
	exit 0
fi
dir=`dirname $0`
$dir/negotiate_kerberos_auth_test $1 | awk '{sub(/Token:/,"YR"); print $0}END{print "QQ"}' | $dir/negotiate_kerberos_auth -d
