#!/bin/sh
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

url=$1
proxy=${2:-localhost}
port=${3:-3128}

if [ $# -lt 1 ]; then
    echo "Usage: $0 URL [server port]"
    exit 1
fi

echo   "blob		# partial message"
echo   "SLEEP=..	# Delay. Can be combined with the others by using ;"
echo   "USER=...	# Success"
echo   "BAD..		# Helper failure"
echo   "ERR..		# Login Failure"

while read auth; do
	echo "GET $url HTTP/1.0"
	if [ -n "$auth" ]; then
		echo "Proxy-Authorization: Negotiate $auth"
	fi
	echo "Proxy-Connection: keep-alive"
	echo
done | tee -a /dev/fd/2 | nc localhost 3128
