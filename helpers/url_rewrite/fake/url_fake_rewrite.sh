#!/bin/sh
#
# Author: Amos Jeffries <squid3@treenet.co.nz>
#
# This code is copyright (C) 2009 by Treehouse Networks Ltd
# of New Zealand. It is published and Licensed as an extension of
# squid under the same conditions as the main squid application.
#

if test "${1}" = "-d" ; then
	echo "Usage: $0 [-h] [-d logfile]"
	echo "  -h           Help: this help text"
	echo "  -d logfile   Debug: log all data received to the named file"
	exit 1
fi

DEBUG=0
if test "${1}" = "-d" ; then
	DEBUG=1
	LOG="${2}"
fi

while read url rest; do
	if test ${DEBUG} ; then
		echo "$url $rest" >>${LOG}
	fi
	echo  # blank line for no change, or replace with another URL.
done
