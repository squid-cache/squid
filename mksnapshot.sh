#!/bin/sh -e

if [ $# -gt 1 ]; then
	echo "Usage: $0 [branch]"
	echo "Where [branch] is the path under /bzr/ to the branch to snapshot."
	exit 1
fi
# VCS details
module=squid3
BZRROOT=${BZRROOT:-/bzr}

# generate a tarball name from the branch ($1) note that trunk is at
# /bzr/trunk, but we call it HEAD for consistency with CVS (squid 2.x), and
# branches are in /bzr/branches/ but we don't want 'branches/' in the tarball
# name so we strip that.
tag="HEAD"
branchpath=${1:-trunk}
if [ "trunk" != "$branchpath" ]; then
    tag=`echo $branchpath | sed -e "s/^branches\///"`
fi
startdir=$PWD
date=`env TZ=GMT date +%Y%m%d`

tmpdir=${TMPDIR:-${PWD}}/${module}-${tag}-mksnapshot

rm -rf $tmpdir
trap "rm -rf $tmpdir" 0

rm -f ${tag}.out
bzr export $tmpdir $BZRROOT/$branchpath || exit 1
if [ ! -f $tmpdir/configure ]; then
	echo "ERROR! Tag $tag not found in $module"
fi

cd $tmpdir
eval `grep "^ *VERSION=" configure | sed -e 's/-BZR//'`
eval `grep "^ *PACKAGE=" configure`
ed -s configure.in <<EOS
g/${VERSION}-BZR/ s//${VERSION}-${date}/
w
EOS
ed -s configure <<EOS
g/${VERSION}-BZR/ s//${VERSION}-${date}/
w
EOS

./configure --silent
make -s dist-all

basetarball=/server/httpd/htdocs/squid-cache.org/Versions/v`echo $VERSION | cut -d. -f1`/`echo $VERSION | cut -d. -f-2|cut -d- -f1`/${PACKAGE}-${VERSION}.tar.bz2
if (echo $VERSION | grep PRE) || (echo $VERSION | grep STABLE); then
	echo "Differences from ${PACKAGE}-${VERSION} to ${PACKAGE}-${VERSION}-${date}" >${PACKAGE}-${VERSION}-${date}.diff
	if [ -f $basetarball ]; then
		tar jxf ${PACKAGE}-${VERSION}-${date}.tar.bz2
		tar jxf $basetarball
		diff -ruN ${PACKAGE}-${VERSION} ${PACKAGE}-${VERSION}-${date} >>${PACKAGE}-${VERSION}-${date}.diff || true
	else
		cvs -q rdiff -u -r SQUID_`echo $VERSION | tr .- __` -r $tag $module >>${PACKAGE}-${VERSION}-${date}.diff || true
	fi
elif [ -f STABLE_BRANCH ]; then
	stable=`cat STABLE_BRANCH`
	echo "Differences from ${stable} to ${PACKAGE}-${VERSION}-${date}" >${PACKAGE}-${VERSION}-${date}.diff
	cvs -q rdiff -u -r $stable -r $tag $module >>${PACKAGE}-${VERSION}-${date}.diff
fi

cd $startdir
cp -p $tmpdir/${PACKAGE}-${VERSION}-${date}.tar.gz .
echo ${PACKAGE}-${VERSION}-${date}.tar.gz >>${tag}.out
cp -p $tmpdir/${PACKAGE}-${VERSION}-${date}.tar.bz2 .
echo ${PACKAGE}-${VERSION}-${date}.tar.bz2 >>${tag}.out
if [ -f $tmpdir/${PACKAGE}-${VERSION}-${date}.diff ]; then
    cp -p $tmpdir/${PACKAGE}-${VERSION}-${date}.diff .
    echo ${PACKAGE}-${VERSION}-${date}.diff >>${tag}.out
fi

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

if [ -x $tmpdir/scripts/www/build-cfg-help.pl ]; then
	make -C $tmpdir/src cf.data
	mkdir -p $tmpdir/doc/cfgman
	$tmpdir/scripts/www/build-cfg-help.pl --version ${VERSION} -o $tmpdir/doc/cfgman $tmpdir/src/cf.data
	sh -c "cd $tmpdir/doc/cfgman && tar -zcf $PWD/${PACKAGE}-${VERSION}-${date}-cfgman.tar.gz *"
	echo ${PACKAGE}-${VERSION}-${date}-cfgman.tar.gz >>${tag}.out
	$tmpdir/scripts/www/build-cfg-help.pl --version ${VERSION} -o ${PACKAGE}-${VERSION}-${date}-cfgman.html -f singlehtml $tmpdir/src/cf.data
	gzip -f -9 ${PACKAGE}-${VERSION}-${date}-cfgman.html
	echo ${PACKAGE}-${VERSION}-${date}-cfgman.html.gz >>${tag}.out
fi
