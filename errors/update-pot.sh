#!/bin/sh
#
# Update the core errpages.pot file from the basic templates
# Useful if any template has altered.
#
# To be run during maintenance from the squid errors/ directory
#

# Make sure any existing temp stuff is gone from previous updates...
rm -rf ./pot
rm -f errpages.pot.new
rm errpages.pot

# make a temp directory for all our workings...
mkdir pot

# Generate per-page disctionaries ...
for f in `ls -1 ./templates/`; do
	if test "${f}" != "generic" ; then
		html2po -i ./templates/${f} -P --duplicates=merge -o ./pot/${f}.pot
	fi
done

# merge and sort the per-page .pot into a single master
msgcat ./pot/*.pot -s -o errpages.pot.new &&
	(
	cat errpages.pot.new | 
	sed s/PACKAGE\ VERSION/Squid-3/ |
	sed s/LANGUAGE\ \<LL\@li\.org\>/Squid\ Developers\ \<squid-dev\@squid-cache\.org\>/
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
