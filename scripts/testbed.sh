#!/bin/sh

# cron Preparation Needed:
# 	cd ~/squid-3 && /bin/sh ./scripts/testbed.sh <machine-name> <your-email>
#

(
# report email headers
	echo "To: noc@squid-cache.org"
	echo "From: ${2}"
	echo "Subject: Build Test on ${1}"
	echo ""

# system details
	echo -n "SYSTEM: " && uname -rsim
	echo -n "DATE:   " && date
	echo -n "SQUID:" && (bzr info | grep "checkout of branch")

# build results
	bzr update 2>&1
	./bootstrap.sh
	./test-builds.sh --cleanup

) | /usr/sbin/sendmail -t
