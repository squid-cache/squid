#!/bin/sh
url=$1
proxy=${2:-localhost}
port=${3:-3128}

if [ $# -lt 1 ]; then
    echo "Usage: $0 URL [server port]"
    exit 1
fi

echo "blob		# partial message"
echo "USER=...		# Success"
echo "BAD..		# Login failure"
echo "ERR..		# Failure"

while read auth; do
	echo "GET $url HTTP/1.0"
	if [ -n "$auth" ]; then
		echo "Proxy-Authorization: NTLM $auth"
	fi
	echo "Proxy-Connection: keep-alive"
	echo
done | tee -a /dev/fd/2 | nc $proxy $port
