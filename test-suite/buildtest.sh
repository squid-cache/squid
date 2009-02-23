#!/bin/sh
#
# Configure and run a test build against any given set of configure options
# or compile-time flags.
#
# Should be run from the source package root directory with paths relative to there.
#

dist="${1}"
base="`dirname $0`"

if test -e ${dist%%.opts}.opts ; then
	echo "BUILD: ${dist%%.opts}.opts"
	. ${dist%%.opts}.opts
else
	echo "BUILD: DEFAULT"
	OPTS=""
	FLAGS=""
fi

#
# empty all the existing code, reconfigure and builds test code
# but skip if we have no files to remove.
# AYJ: 1 because we already created the build log
FILECOUNT=`ls -1 | grep -c .`
if test "$FILECOUNT" != "1" ; then
  make -k distclean || echo "distclean done. errors are unwanted but okay here."
fi

#
# above command currently encounters dependancy problems on cleanup.
#
rm -f -r src/fs/aufs/.deps src/fs/diskd/.deps &&
	$base/../configure --silent ${OPTS} 2>&1 &&
	make check 2>&1 &&
	make 2>&1

# do not build any of the install's ...
