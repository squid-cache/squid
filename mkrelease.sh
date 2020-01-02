#!/bin/sh -ex
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

if [ $# -ne 1 -a $# -ne 2 ]; then
	echo "Usage: $0 revision [destination]"
	exit 1
fi

# infer tags from command line details
package=squid
rev=`echo $1 | sed -e "s/^${package}-//"`
name=${package}-${rev}
tag=`echo ${name} | tr a-z.- A-Z__`
startdir=$PWD/
dst=${2:-$PWD}/
RELEASE_TIME=`date +%s`

# DPW 2007-08-30
#
# check that $rev has the right syntax
#
checkrev=`expr $rev : '\([0-9]\.[0-9]\(\.[0-9\.]\)*\)'`
if test "$rev" != "$checkrev" ; then
	echo "revision '$rev' has incorrect syntax.  Should be like '3.1.0.1'"
	exit 1;
fi

tmpdir=${TMPDIR:-${PWD}}/${name}-mkrelease

rm -rf $name.tar.gz $tmpdir
trap "rm -rf $tmpdir" 0

mkdir ${tmpdir}
(git archive --format=tar HEAD | tar -xC ${tmpdir}) || exit 1

if [ ! -f $tmpdir/bootstrap.sh ]; then
	echo "ERROR! Tag $tag not found"
fi

cd $tmpdir
./bootstrap.sh
eval `grep "^ *PACKAGE_VERSION=" configure | sed -e 's/-VCS//' | sed -e 's/PACKAGE_//'`
eval `grep "^ *PACKAGE_TARNAME=" configure | sed -e 's/_TARNAME//'`
if [ ${name} != ${PACKAGE}-${VERSION} ]; then
	echo "ERROR! The tag and configure version numbers do not match!"
	echo "${name} != ${PACKAGE}-${VERSION}"
	exit 1
fi
RELEASE=`echo $VERSION | cut -d. -f1,1 | cut -d- -f1`
NOTES_VERSION=`grep "$VERSION" doc/release-notes/release-${RELEASE}.sgml`
if test "x$NOTES_VERSION" = "x"; then
	echo "ERROR! Release Notes HTML version numbers do not match!"
	exit 1
fi
ed -s configure.ac <<EOS
g/${VERSION}-VCS/ s//${VERSION}/
w
EOS
ed -s configure <<EOS
g/${VERSION}-VCS/ s//${VERSION}/
w
EOS
ed -s include/version.h <<EOS
g/squid_curtime/ s//${RELEASE_TIME}/
w
EOS

./configure --silent --enable-translation
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
inst $tmpdir/README		$dst/README.txt
inst $tmpdir/CREDITS		$dst/CREDITS.txt
inst $tmpdir/SPONSORS		$dst/SPONSORS.txt
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
