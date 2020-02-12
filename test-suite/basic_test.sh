#!/bin/sh
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

while read user password; do
case $password in
UNKNOWN)
	echo "ERR Unknown User"
	;;
OK*)	echo "OK"
	;;
*)	echo "ERR Incorrect Login"
	;;
esac
done
