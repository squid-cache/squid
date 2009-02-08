#!/bin/sh

(
# report email headers
	echo "To: noc@squid-cache.org"
	echo "From: ${2}"
	echo "Subject: Build Test on ${1}"
	echo ""

# system details
	echo -n "SYSTEM: " && /bin/uname -rsim
	echo -n "DATE: " && /bin/date
	echo -n "SQUID: " && (bzr info | grep "public branch")

# build results
	bzr update
	./bootstrap.sh
	./test-builds.sh

) | /usr/sbin/sendmail -t
