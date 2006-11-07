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
g/${VERSION}-CVS/ s//${VERSION}/
w
EOS
ed -s configure <<EOS
g/${VERSION}-CVS/ s//${VERSION}/
w
EOS
ed -s include/version.h <<EOS
g/squid_curtime/ s//${RELEASE_TIME}/
w
EOS

./configure --silent
make dist-all

cd $startdir
inst() {
rm -f $2
cp -p $1 $2
chmod 444 $2
}
inst $tmpdir/${name}.tar.gz	$dst/${name}.tar.gz
inst $tmpdir/${name}.tar.bz2	$dst/${name}.tar.bz2
inst $tmpdir/CONTRIBUTORS	$dst/CONTRIBUTORS.txt
inst $tmpdir/COPYING		$dst/COPYING.txt
inst $tmpdir/COPYRIGHT		$dst/COPYRIGHT.txt
inst $tmpdir/CREDITS		$dst/CREDITS.txt
inst $tmpdir/ChangeLog		$dst/ChangeLog.txt
if [ -f $tmpdir/doc/release-notes/release-$RELEASE.html ]; then
    cat $tmpdir/doc/release-notes/release-$RELEASE.html | sed -e '
	s/"ChangeLog"/"ChangeLog.txt"/g;
    ' > $tmpdir/RELEASENOTES.html
    touch -r $tmpdir/doc/release-notes/release-$RELEASE.html $tmpdir/RELEASENOTES.html
    inst $tmpdir/RELEASENOTES.html $dst/${name}-RELEASENOTES.html
    ln -sf ${name}-RELEASENOTES.html $dst/RELEASENOTES.html
fi
if [ -f $dst/changesets/.update ]; then
    rm -f $dst/changesets/$tag.html
    $dst/changesets/.update
fi
