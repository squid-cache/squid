#!/bin/sh
#
# Configure and run a test build against any given set of configure options
# or compile-time flags.
#
# Should be run from the source package root directory with paths relative to there.
#

config="${1}"
base="`dirname ${0}`"

#if we are on Linux, let's try parallelizing
pjobs="" #default
if [ -e /proc/cpuinfo ]; then
    ncpus=`grep '^processor' /proc/cpuinfo | tail -1|awk '{print $3}'`
    ncpus=`expr ${ncpus} + 1`
    pjobs="-j${ncpus}"
fi

if test -e ${config} ; then
	echo "BUILD: ${config}"
	. ${config}
else
	echo -n "BUILD ERROR: Unable to locate test configuration '${config}' from " && pwd
	exit 1;
fi

#
# empty all the existing code, reconfigure and builds test code
# but skip if we have no files to remove.
FILECOUNT=`ls -1 | grep -c .`
if test "${FILECOUNT}" != "0" ; then
  make -k distclean || echo "distclean done. errors are unwanted but okay here."
fi

#
# above command currently encounters dependancy problems on cleanup.
#
# do not build any of the install's ...
rm -f -r src/fs/aufs/.deps src/fs/diskd/.deps &&
	$base/../configure --silent ${OPTS} 2>&1 &&
	make ${pjobs} ${MAKETEST} 2>&1

# Remember and then explicitly return the result of the last command
# to the script caller. Probably not needed on most or all platforms.
result=$?
exit ${result}
