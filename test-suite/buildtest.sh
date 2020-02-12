#!/bin/sh
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Configure and run a test build against any given set of configure options
# or compile-time flags.
#
# Should be run from the source package root directory with paths relative to there.
#

action="${1}"
config="${2}"
base="`dirname ${0}`"

# cache_file may be set by environment variable
configcache=""
if [ -n "$cache_file" ]; then
    configcache="--cache-file=$cache_file"
fi

#if we are on Linux, let's try parallelizing
if [ -z "$pjobs" -a -e /proc/cpuinfo ]; then
    ncpus=`grep '^processor' /proc/cpuinfo | tail -1|awk '{print $3}'`
    ncpus=`expr ${ncpus} + 1`
    pjobs="-j${ncpus}"
fi
#if we are on FreeBSD, let's try parallelizing
if [ -z "$pjobs" -a -x /sbin/sysctl ]; then
    ncpus=`sysctl kern.smp.cpus | cut -f2 -d" "`
    if [ $? -eq 0 -a -n "$ncpus" -a "$ncpus" -gt 1 ]; then
        pjobs="-j${ncpus}"
    fi
fi

if test -e ${config} ; then
	echo "BUILD: ${config}"
	. ${config}
else
	echo -n "BUILD ERROR: Unable to locate test configuration '${config}' from " && pwd
	exit 1;
fi

# override the layers MAKETEST default
if test "x${action}" != "x"; then
    MAKETEST="${action}"
fi

#
# empty all the existing code, reconfigure and builds test code
# but skip if we have no files to remove.
FILECOUNT=`ls -1 | grep -c .`
if test "${FILECOUNT}" != "0" ; then
  ${MAKE:-make} -k distclean || echo "distclean done. errors are unwanted but okay here."
  ls -la .
  rm -fr ./src/fs/aufs/.deps src/fs/diskd/.deps
fi

#
# above command currently encounters dependancy problems on cleanup.
#
# do not build any of the install's ...
#
# eval is need to correctly handle quoted arguments
	eval "$base/../configure ${DISTCHECK_CONFIGURE_FLAGS} ${configcache}" \
		2>&1 && \
	${MAKE:-make} ${pjobs} ${MAKETEST} 2>&1

# Remember and then explicitly return the result of the last command
# to the script caller. Probably not needed on most or all platforms.
result=$?
exit ${result}
