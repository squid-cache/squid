#!/bin/sh -e
if [ $# -gt 1 ]; then
	echo "Usage: $0 [branch]"
	exit 1
fi
module=squid3
tag=${1:-HEAD}
startdir=$PWD
date=`env TZ=GMT date +%Y%m%d`

tmpdir=${TMPDIR:-${PWD}}/${module}-${tag}-mksnapshot

CVSROOT=${CVSROOT:-/server/cvs-server/squid}
export CVSROOT

rm -rf $tmpdir
trap "rm -rf $tmpdir" 0

rm -f ${tag}.out
cvs -Q export -d $tmpdir -r $tag $module
if [ ! -f $tmpdir/configure ]; then
	echo "ERROR! Tag $tag not found in $module"
fi

cd $tmpdir
eval `grep "^ *VERSION=" configure | sed -e 's/-CVS//'`
eval `grep "^ *PACKAGE=" configure`
ed -s configure.in <<EOS
g/VERSION=${VERSION}-CVS/ s//VERSION=${VERSION}-${date}/
w
EOS
ed -s configure <<EOS
g/VERSION=${VERSION}-CVS/ s//VERSION=${VERSION}-${date}/
w
EOS

./configure --silent
make -s dist-all

cd $startdir
cp -p $tmpdir/${PACKAGE}-${VERSION}-${date}.tar.gz .
echo ${PACKAGE}-${VERSION}-${date}.tar.gz >>${tag}.out
cp -p $tmpdir/${PACKAGE}-${VERSION}-${date}.tar.bz2 .
echo ${PACKAGE}-${VERSION}-${date}.tar.bz2 >>${tag}.out

relnotes=$tmpdir/doc/release-notes/release-`echo $VERSION | cut -d. -f1,2 | cut -d- -f1`.html
if [ -f $relnotes ]; then
	cp -p $relnotes ${PACKAGE}-${VERSION}-${date}-RELEASENOTES.html
	echo ${PACKAGE}-${VERSION}-${date}-RELEASENOTES.html >>${tag}.out
	ed -s ${PACKAGE}-${VERSION}-${date}-RELEASENOTES.html <<EOF
g/"ChangeLog"/ s//"${PACKAGE}-${VERSION}-${date}-ChangeLog.txt"/g
w
EOF
fi
cp -p $tmpdir/ChangeLog ${PACKAGE}-${VERSION}-${date}-ChangeLog.txt
echo ${PACKAGE}-${VERSION}-${date}-ChangeLog.txt >>${tag}.out

if (echo $VERSION | grep PRE) || (echo $VERSION | grep STABLE); then
  echo "Differences from ${PACKAGE}-${VERSION} to ${PACKAGE}-${VERSION}-${date}" >${PACKAGE}-${VERSION}-${date}.diff
  cvs -q rdiff -u -r SQUID_`echo $VERSION | tr .- __` -r $tag $module >>${PACKAGE}-${VERSION}-${date}.diff
  echo ${PACKAGE}-${VERSION}-${date}.diff >>${tag}.out
fi
