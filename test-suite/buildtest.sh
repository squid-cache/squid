#!/bin/sh -ex
#
# Configure and run a test build against any given set of configure options
# or compile-time flags.
#
# Should be run from the source package root directory with paths relative to there.
#

dist="${1}"

# Figure out where to log the test output
log=`echo "${dist}" | sed s/..test-suite.buildtests.//g `

# ... and send everything there...
{

if test -x ${dist%%.opts}.opts ; then
	echo "BUILD: ${dist%%.opts}.opts"
	. ./${dist%%.opts}.opts
else
	echo "BUILD: DEFAULT"
	OPTS=""
fi

if test -f ${dist%%.opts}.flags ; then
#	echo "DEBUG: ${dist%%.opts}.flags"
	FLAGS=`cat ./${dist%%.opts}.flags`
# else nothing set for flags.
fi

#
# empty all the existing code, reconfigure and builds test code

make -k distclean || echo "distclean done. errors are unwanted but okay here."

#
# above command currently encounters dependancy problems on cleanup.
#
rm -f -r src/fs/aufs/.deps src/fs/diskd/.deps &&
	./bootstrap.sh &&
	./configure ${OPTS} &&
	make check &&
	make

} 2>&1 > ./buildtest_${log}.log

# do not build any of the install's ...
