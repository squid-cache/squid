#!/bin/sh -ex
if [ $# -ne 1 -a $# -ne 2 ]; then
	echo "Usage: $0 revision [destination]"
	exit 1
fi
package=squid
module=squid3
rev=`echo $1 | sed -e "s/^${package}-//"`
name=${package}-${rev}
tag=`echo ${name} | tr a-z.- A-Z__`
startdir=$PWD/
dst=${2:-$PWD}/
RELEASE_TIME=`date +%s`

tmpdir=${TMPDIR:-${PWD}}/${name}-mkrelease

CVSROOT=${CVSROOT:-/server/cvs-server/squid}
export CVSROOT

rm -rf $name.tar.gz $tmpdir
trap "rm -rf $tmpdir" 0

cvs -Q export -d $tmpdir -r $tag $module
if [ ! -f $tmpdir/configure ]; then
	echo "ERROR! Tag $tag not found in $module"
fi

cd $tmpdir
eval `grep "^ *VERSION=" configure | sed -e 's/-CVS//'`
eval `grep "^ *PACKAGE=" configure`
if [ ${name} != ${PACKAGE}-${VERSION} ]; then
	echo "ERROR! The version numbers does not match!"
	echo "${name} != ${PACKAGE}-${VERSION}"
	exit 1
fi
RELEASE=`echo $VERSION | cut -d. -f1,2 | cut -d- -f1`
ed -s configure.in <<EOS
g/VERSION=${VERSION}-CVS/ s//VERSION=${VERSION}-${date}/
w
EOS
ed -s configure <<EOS
g/VERSION=${VERSION}-CVS/ s//VERSION=${VERSION}-${date}/
w
EOS
ed -s include/version.h <<EOS
g/squid_curtime/ s//${RELEASE_TIME}/
w
EOS

./configure --silent
make dist-all

cd $startdir
cp -p $tmpdir/${name}.tar.gz	$dst
cp -p $tmpdir/${name}.tar.bz2	$dst
cp -p $tmpdir/CONTRIBUTORS	$dst/CONTRIBUTORS.txt
cp -p $tmpdir/COPYING		$dst/COPYING.txt
cp -p $tmpdir/COPYRIGHT		$dst/COPYRIGHT.txt
cp -p $tmpdir/CREDITS		$dst/CREDITS.txt
cp -p $tmpdir/ChangeLog		$dst/ChangeLog.txt
if [ -f $tmpdir/doc/release-notes/release-$RELEASE.html ]; then
    cp -p $tmpdir/doc/release-notes/release-$RELEASE.html $dst/RELEASENOTES.html
fi
