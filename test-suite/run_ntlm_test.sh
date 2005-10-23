#!/bin/sh
while read auth; do
	echo "HEAD http://www.squid-cache.org/ HTTP/1.0"
	if [ -n "$auth" ]; then
		echo "Proxy-Authorization: NTLM $auth"
	fi
	echo "Proxy-Connection: keep-alive"
	echo
done | tee -a /dev/fd/2 | nc localhost 3128
