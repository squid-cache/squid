#!/bin/sh
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

#
# Update the core errpages.pot file from the basic templates
# Useful if any template has altered.
#
# To be run during maintenance from the main squid directory
#

## Begin errors/ Updates.

cd errors/
# Make sure any existing temp stuff is gone from previous updates...
rm -rf ./pot
rm -f errpages.pot.new
rm errpages.pot

# make a temp directory for all our workings...
mkdir pot

# Generate per-page dictionaries ...
for f in `ls -1 ./templates/`; do
	case ${f} in
	error-details.txt)
		../scripts/mk-error-details-po.pl ./templates/${f} > ./pot/${f}.pot
		;;
	ERR_*)
		html2po -i ./templates/${f} -P --duplicates=merge -o ./pot/${f}.pot
		;;
	*)
		echo "SKIP: ${f}"
	esac
done

# merge and sort the per-page .pot into a single master
msgcat ./pot/*.pot -s -o errpages.pot.new &&
	(
	cat errpages.pot.new |
	sed s/PACKAGE\ VERSION/Squid-5/ |
	sed s/LANGUAGE\ \<LL\@li\.org\>/Squid\ Developers\ \<squid-dev\@lists.squid-cache\.org\>/
	) >errpages.pot

## Update all existing dictionaries with the new content ...
for f in `ls -1 ./*.po` ; do
	echo -n "Update: ${f} ... "
	msgmerge --verbose -s -o ${f}.new ${f} errpages.pot
	chown --reference=${f} ${f}.new
	mv ${f}.new ${f}
done

# cleanup.
rm -rf pot
rm -f errpages.pot.new
cd ..
## Done errors/ Updates


## begin doc/manuals updates

# Build the po4a.conf
cat doc/po4a.cnf >po4a.conf
for f in `ls -1 \
	src/*.8.in \
	src/auth/*/*/*.8 \
	src/acl/external/*/*.8 \
	src/http/url_rewriters/*/*.8 \
	src/log/*/*.8 \
	src/security/*/*/*.8 \
	src/security/*/*/*.8.in \
	src/src/store/id_rewriters/*/*.8 \
	tools/*/*.1 \
	tools/*.8.in \
` ; do
	echo "" >>po4a.conf
	manp=`basename ${f}`
	echo "[type: man] ${f} \$lang:doc/manuals/\$lang/${manp}" >>po4a.conf
done

## po4a conversion of all doc/manuals man files...
po4a --no-translations -o groff_code=verbatim --verbose po4a.conf

(
	cat doc/manuals/manuals.pot |
	sed s/PACKAGE\ VERSION/Squid-5/ |
	sed s/LANGUAGE\ \<LL\@li\.org\>/Squid\ Developers\ \<squid-dev\@lists.squid-cache\.org\>/
) >doc/manuals/manuals.pot.tmp
mv doc/manuals/manuals.pot.tmp doc/manuals/manuals.pot

## Done doc/manuals/ Update
