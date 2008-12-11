#!/bin/sh
#
# Update the core dictionary file from the basic templates
# Useful if any template has altered.
#

# Make sure any existing temp stuff is gone from previous updates...
rm -r -f ./pot
rm -f dictionary.pot.new
rm dictionary.pot

# make a temp directory for all our workings...
mkdir ./pot

# Generate per-page disctionaries ...
for f in `ls -1 ./templates/`; do
	if test "${f}" != "generic" ; then
		html2po -i ./templates/${f} -P --duplicates=merge -o ./pot/${f}.pot
	fi
done

# merge and sort the per-page dictionaries into a single master
msgcat ./pot/*.pot -s -o dictionary.pot.new &&
	(
	cat dictionary.pot.new | 
	sed s/PACKAGE\ VERSION/Squid-3/ |
	sed s/LANGUAGE\ \<LL\@li\.org\>/Squid\ Developers\ \<squid-dev\@squid-cache\.org\>/
	) >dictionary.pot

## Update all existing dictionaries with the new content ...
for f in `ls -1 ./*.po` ; do
	echo -n "Update: ${f} ... "
	msgmerge --verbose -s -o ${f}.new ${f} dictionary.pot
	chown --reference=${f} ${f}.new
	mv ${f}.new ${f}
done

# cleanup.
rm -r -f ./pot
rm -f dictionary.pot.new
