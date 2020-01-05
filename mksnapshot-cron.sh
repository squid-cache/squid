#!/bin/sh -e
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

echo "RUN: $0"
# Nightly cron job to generate snapshot releases
top=${PWD}
versions=/server/httpd/htdocs/squid-cache.org/content/Versions/
TMPDIR=/home/squidadm/${LOGNAME}.cron
export TMPDIR
if [ -d ${TMPDIR} ]; then
	chmod -R +w ${TMPDIR}
	rm -rf ${TMPDIR}
fi
mkdir -p ${TMPDIR}
trap "echo FAIL-BUILD_snapshot-cron; cd /; chmod -R +w ${TMPDIR}; rm -rf ${TMPDIR}" 0

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin
export PATH

# Be nice to our friends. This is a batch job
renice 10 $$ >/dev/null

make_snapshot()
{ {
  set -e
  cd ../release
  mksnap=${1}
  branch=${2}
  dir=${3}
  ver=${4}
  save=${5:-3}
  dst=${versions}/${dir}/${ver}
  out=${6:-`basename $branch`}
  $mksnap ${branch} ${6} 2>&1 | grep -v "set owner/group"
  for file in `cat ${out}.out` ; do
    case ${file} in
    *-cfgman.tar.gz)
	type=-cfgman.tar.gz
	;;
    *-langpack.tar.gz)
	type=-langpack.tar.gz
	;;
    *-manuals.tar.gz)
	type=-manuals.tar.gz
	;;
    *)
	type=`echo ${file} | sed -e 's/.*\.tar\.gz/.tar.gz/' -e 's/.*\.tar\.bz2/.tar.bz2/' -e 's/.*\.patch/.patch/' -e 's/.*\.diff/.diff/' -e 's/.*-RELEASENOTES.html/-RELEASENOTES.html/' -e 's/^.*ChangeLog.txt$/-ChangeLog.txt/' -e 's/.*-cfgman/-cfgman/'`
    esac

    # move tarball
    rm -f ${dst}/${file}.md5
    rm -f ${dst}/${file}
    md5 ${file} >${dst}/${file}.md5
    cp -p ${file} ${dst}/${file}
    rm -f ${file}

    # update snapshot symlink
    rm -f ${dst}/squid-${ver}.snapshot$type
    ln -s ${file} ${dst}/squid-${ver}.snapshot${type}
    rm -f ${dst}/squid-${ver}.snapshot${type}.md5
    ln -s ${file}.md5 ${dst}/squid-${ver}.snapshot${type}.md5

  set +e
    # cleanup old snapshots
    ls ${dst}/*-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-r*[0-9]${type} | \
#		sed -e 's/.*-\([0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-r[0-9]+'${type}'\)/\1/' | \
		sort -r | tail +${save} | \
    while read f; do
	rm -f ${f} ${f}.md5
    done
  set -e

    # update dynamic index pages Last-Modified info
    touch ${dst}/index.dyn

    # Special cases
    case ${file} in
    *-cfgman.tar.gz)
	mkdir -p ${dst}/cfgman
	tar -C ${dst}/cfgman -zxf ${dst}/${file}
	;;
    *-cfgman.html)
	rm -f ${dst}/cfgman.html
	ln -s ${dst}/${file} ${dst}/cfgman.html
	;;
    *-cfgman.html.gz)
	rm -f ${dst}/cfgman.html.gz
	ln -s ${dst}/${file} ${dst}/cfgman.html.gz
	;;
    *-manuals.tar.gz)
	mkdir -p ${dst}/manuals
	tar -C ${dst}/manuals -zxf ${dst}/${file}
	;;
    esac
  done
} }

set +e

# autotool derived files not kept in trunk, but still need to bootstrap for make dist
#../commit/bootstrap squid-3
#make_snapshot ../commit/squid-3/mksnapshot.sh trunk v3 3.HEAD 6

#rm -f /server/httpd/htdocs/squid-cache.org/CONTRIBUTORS.new
#cp ../commit/squid-3/CONTRIBUTORS /server/httpd/htdocs/squid-cache.org/CONTRIBUTORS.new
#chmod 444 /server/httpd/htdocs/squid-cache.org/CONTRIBUTORS.new
#mv -f /server/httpd/htdocs/squid-cache.org/CONTRIBUTORS.new /server/httpd/htdocs/squid-cache.org/content/CONTRIBUTORS.txt
#
#rm -f /server/httpd/htdocs/squid-cache.org/SPONSORS.new
#cp ../commit/squid-3/SPONSORS /server/httpd/htdocs/squid-cache.org/SPONSORS.new
#chmod 444 /server/httpd/htdocs/squid-cache.org/SPONSORS.new
#mv -f /server/httpd/htdocs/squid-cache.org/SPONSORS.new /server/httpd/htdocs/squid-cache.org/content/SPONSORS.txt

../commit/bootstrap squid-3.4
make_snapshot ../commit/squid-3/mksnapshot.sh 3.4 v3 3.4 30

../commit/bootstrap squid-3.3
make_snapshot ../commit/squid-3/mksnapshot.sh 3.3 v3 3.3 30

#../commit/bootstrap squid-3.2
#make_snapshot ../commit/squid-3/mksnapshot.sh branches/SQUID_3_2 v3 3.2 30

#../commit/bootstrap squid-3.1
#make_snapshot ../commit/squid-3/mksnapshot.sh branches/SQUID_3_1 v3 3.1 30

#../commit/bootstrap squid-3.0
#make_snapshot ../commit/squid-3/mksnapshot.sh branches/SQUID_3_0 v3 3.0 3

#../commit/bootstrap squid-2
#make_snapshot ../commit/squid-2/mksnapshot.sh HEAD v2 HEAD 3

#../commit/bootstrap squid-2.7
#make_snapshot ../commit/squid-2.7/mksnapshot.sh SQUID_2_7 v2 2.7 3

#../commit/bootstrap squid-2.6
#make_snapshot ../commit/squid-2.6/mksnapshot.sh SQUID_2_6 v2 2.6 3

#../commit/bootstrap squid-2.5
#make_snapshot ../commit/squid-2.5/mksnapshot.sh SQUID_2_5 v2 2.5 3

#../commit/squid3-SQUID2.sync


../commit/bootstrap squid-3.5
make_snapshot ../commit/squid-3/mksnapshot.sh 3.5 v3 3.5 30

