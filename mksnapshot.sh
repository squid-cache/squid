#!/bin/sh -e
#
## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

echo "RUN: $0"
if [ $# -lt 1 ]; then
	echo "Usage: $0 [branch]"
	echo "Where [branch] is the path under /bzr/ to the branch to snapshot."
	exit 1
fi
# VCS details
module=squid3
BZRROOT=${BZRROOT:-/bzr}

# generate a tarball name from the branch ($1) note that trunk is at
# /bzr/trunk, but we call it 3.HEAD for consistency with CVS (squid 2.x), and
# branches are in /bzr/branches/ but we don't want 'branches/' in the tarball
# name so we strip that.
branchpath=${1:-trunk}
tag=${2:-`basename $branchpath`}
startdir=${PWD}
date=`env TZ=GMT date +%Y%m%d`

tmpdir=${TMPDIR:-${PWD}}/${module}-${tag}-mksnapshot

rm -rf ${tmpdir}
trap "echo FAIL-BUILD_${VERSION} ; rm -rf ${tmpdir}" 0

rm -f ${tag}.out
bzr export ${tmpdir} ${BZRROOT}/${module}/${branchpath} || exit 1
if [ ! -f ${tmpdir}/configure ] && [ -f ${tmpdir}/configure.ac ]; then
	sh -c "cd ${tmpdir} && ./bootstrap.sh"
fi
if [ ! -f ${tmpdir}/configure ]; then
	echo "ERROR! Tag ${tag} not found in ${module}"
fi

cd ${tmpdir}
revision=`bzr revno ${BZRROOT}/${module}/${branchpath}`
suffix="${date}-r${revision}"
eval `grep "^ *PACKAGE_VERSION=" configure | sed -e 's/-BZR//' | sed -e 's/PACKAGE_//'`
eval `grep "^ *PACKAGE_TARNAME=" configure | sed -e 's/_TARNAME//'`
ed -s configure.ac <<EOS
g/${VERSION}-[A-Z]*/ s//${VERSION}-${suffix}/
w
EOS
ed -s configure <<EOS
g/${VERSION}-[A-Z]*/ s//${VERSION}-${suffix}/
w
EOS

echo "STATE..."
echo "PACKAGE: ${PACKAGE}"
echo "VERSION: ${VERSION}"
echo "TAG: ${tag}"
echo "REVISION: ${revision}"
echo "STARTDIR: ${startdir}"
echo "TMPDIR: ${tmpdir}"

## Ignore extra build layers. General features building is sufficient for snapshot release.
./test-builds.sh --cleanup layer-00-default layer-01-minimal layer-02-maximus || exit 1
./configure --silent --enable-build-info="DATE: ${date} REVISION: ${revision}" --enable-translation
make -s dist-all

webbase=/server/httpd/htdocs/squid-cache.org/content/
basetarball=${webbase}/Versions/v`echo ${VERSION} | cut -d. -f1`/`echo ${VERSION} | cut -d. -f-2|cut -d- -f1`/${PACKAGE}-${VERSION}.tar.bz2

echo "Building Tarball diff (${basetarball}) ..."
if [ -f ${basetarball} ]; then
	tar jxf ${PACKAGE}-${VERSION}-${suffix}.tar.bz2
	tar jxf ${basetarball}
	echo "Differences from ${PACKAGE}-${VERSION} to ${PACKAGE}-${VERSION}-${suffix}" >${PACKAGE}-${VERSION}-${suffix}.diff
	diff -ruN ${PACKAGE}-${VERSION} ${PACKAGE}-${VERSION}-${suffix} >>${PACKAGE}-${VERSION}-${suffix}.diff || true
else
	echo "Building Tarball diff ... skipped (no tarball exists)."
fi

cd ${startdir}
echo "Preparing to publish: ${tmpdir}/${PACKAGE}-${VERSION}-${suffix}.tar.* ..."
#echo "LOCAL: " ; pwd
#echo "BUILT TARS: " ; ls -1 ${tmpdir}/*.tar.* || true

cp -p ${tmpdir}/${PACKAGE}-${VERSION}-${suffix}.tar.gz .
echo ${PACKAGE}-${VERSION}-${suffix}.tar.gz >>${tag}.out
cp -p ${tmpdir}/${PACKAGE}-${VERSION}-${suffix}.tar.bz2 .
echo ${PACKAGE}-${VERSION}-${suffix}.tar.bz2 >>${tag}.out
if [ -f ${tmpdir}/${PACKAGE}-${VERSION}-${suffix}.diff ]; then
    cp -p ${tmpdir}/${PACKAGE}-${VERSION}-${suffix}.diff .
    echo ${PACKAGE}-${VERSION}-${suffix}.diff >>${tag}.out
fi

relnotes=${tmpdir}/doc/release-notes/release-`echo ${VERSION} | cut -d. -f1,2 | cut -d- -f1`.html
if [ -f ${relnotes} ]; then
	cp -p ${relnotes} ${PACKAGE}-${VERSION}-${suffix}-RELEASENOTES.html
	echo ${PACKAGE}-${VERSION}-${suffix}-RELEASENOTES.html >>${tag}.out
	ed -s ${PACKAGE}-${VERSION}-${suffix}-RELEASENOTES.html <<EOF
g/"ChangeLog"/ s//"${PACKAGE}-${VERSION}-${suffix}-ChangeLog.txt"/g
w
EOF
fi
cp -p ${tmpdir}/ChangeLog ${PACKAGE}-${VERSION}-${suffix}-ChangeLog.txt
echo ${PACKAGE}-${VERSION}-${suffix}-ChangeLog.txt >>${tag}.out

# Generate Configuration Manual HTML
if [ -x ${tmpdir}/scripts/www/build-cfg-help.pl ]; then
	make -C ${tmpdir}/src cf.data
	mkdir -p ${tmpdir}/doc/cfgman
	${tmpdir}/scripts/www/build-cfg-help.pl --version ${VERSION} -o ${tmpdir}/doc/cfgman ${tmpdir}/src/cf.data
	sh -c "cd ${tmpdir}/doc/cfgman && tar -zcf ${PWD}/${PACKAGE}-${VERSION}-${suffix}-cfgman.tar.gz *"
	echo ${PACKAGE}-${VERSION}-${suffix}-cfgman.tar.gz >>${tag}.out
	${tmpdir}/scripts/www/build-cfg-help.pl --version ${VERSION} -o ${PACKAGE}-${VERSION}-${suffix}-cfgman.html -f singlehtml ${tmpdir}/src/cf.data
	gzip -f -9 ${PACKAGE}-${VERSION}-${suffix}-cfgman.html
	echo ${PACKAGE}-${VERSION}-${suffix}-cfgman.html.gz >>${tag}.out
fi

# Collate Manual Pages and generate HTML versions
if (groff --help >/dev/null); then
	make -C ${tmpdir}/src squid.8
	if [ ! -d ${tmpdir}/doc/manuals ] ; then
		mkdir -p ${tmpdir}/doc/manuals
	fi
	for f in `ls -1 ${tmpdir}/helpers/*/*/*.8 ${tmpdir}/src/*.8 ${tmpdir}/src/*/*.8 ${tmpdir}/tools/squidclient/*.1 ${tmpdir}/tools/*.8 ./helpers/*/*/*.8 2>/dev/null` ; do
		cp $f ${tmpdir}/doc/manuals/
	done
	for f in `ls -1 ${tmpdir}/doc/manuals/*.1  ${tmpdir}/doc/manuals/*.8 2>/dev/null` ; do
		cat ${f} | groff -E -Thtml -mandoc >${f}.html
	done
	sh -c "cd ${tmpdir}/doc/manuals && tar -zcf ${PWD}/${PACKAGE}-${VERSION}-${suffix}-manuals.tar.gz *.html *.1 *.8"
	echo ${PACKAGE}-${VERSION}-${suffix}-manuals.tar.gz >>${tag}.out
fi

# Generate language-pack tarballs
# NP: Only to be done on trunk.
if test "${tag}" = "trunk" ; then
	sh -c "cd ${tmpdir}/errors && tar -zcf ${PWD}/${PACKAGE}-${VERSION}-${suffix}-langpack.tar.gz ./*/* ./alias* ./TRANSLATORS ./COPYRIGHT "
	echo ${PACKAGE}-${VERSION}-${suffix}-langpack.tar.gz >>${tag}.out
fi
