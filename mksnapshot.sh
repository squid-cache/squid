#!/bin/sh -e
if [ $# -gt 1 ]; then
	echo "Usage: $0 [branch]"
	exit 1
fi
module=squid3
tag=${1:-HEAD}
startdir=$PWD
date=`env TZ=GMT date +%Y%m%d`

tmpdir=$PWD/${module}-${tag}-mksnapshot

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
eval CVS`grep ^VERSION= configure`
VERSION=`echo $CVSVERSION | sed -e 's/-CVS//'`
eval `grep ^PACKAGE= configure`
ed -s configure.in <<EOS
g/${CVSVERSION}/ s//${VERSION}-${date}/
w
EOS
ed -s configure <<EOS
g/${CVSVERSION}/ s//${VERSION}-${date}/
w
EOS

./configure --silent
make -s dist-all

cd $startdir
cp -p $tmpdir/${PACKAGE}-${VERSION}-${date}.tar.gz .
cp -p $tmpdir/${PACKAGE}-${VERSION}-${date}.tar.bz2 .

echo ${PACKAGE}-${VERSION}-${date}.tar.gz >>${tag}.out
echo ${PACKAGE}-${VERSION}-${date}.tar.bz2 >>${tag}.out

if (echo $VERSION | grep PRE) || (echo $VERSION | grep STABLE); then
  echo "Differences from ${PACKAGE}-${VERSION} to ${PACKAGE}-${VERSION}-${date}" >${PACKAGE}-${VERSION}-${date}.diff
  cvs -q rdiff -u -r SQUID_`echo $VERSION | tr .- __` -r $tag $module >>${PACKAGE}-${VERSION}-${date}.diff
  echo ${PACKAGE}-${VERSION}-${date}.diff >>${tag}.out
fi
