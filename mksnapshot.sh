#!/bin/sh -e
if [ $# -gt 1 ]; then
	echo "Usage: $0 [branch]"
	exit 1
fi
package=squid
tag=${1:-HEAD}
startdir=$PWD
date=`date +%Y%m%d`

tmpdir=$PWD/${package}-${tag}-mksnapshot

CVSROOT=${CVSROOT:-/server/cvs-server/squid}
export CVSROOT

rm -rf $tmpdir
trap "rm -rf $tmpdir" 0

cvs -Q export -d $tmpdir -r $tag $package
if [ ! -f $tmpdir/configure ]; then
	echo "ERROR! Tag $tag not found in $package"
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
make dist-all

cd $startdir
cp -p $tmpdir/${PACKAGE}-${VERSION}-${date}.tar.gz .
cp -p $tmpdir/${PACKAGE}-${VERSION}-${date}.tar.bz2 .

echo ${PACKAGE}-${VERSION}-${date}.tar.gz >${tag}.out
echo ${PACKAGE}-${VERSION}-${date}.tar.bz2 >>${tag}.out
