#/bin/sh
#
# Update the core dictionary file from the basic templates
# Useful if any template has altered.
#

# Make sure any existing temp stuff is gone from previous updates...
rm -r -f ./pot
rm -f dictionary.pot.new

# make a temp directory for all our workings...
mkdir ./pot

# Generate per-page disctionaries ...
for f in `ls -1 ./templates/`; do
	html2po -i ./templates/${f} -P --duplicates=merge -o ./pot/${f}.pot
done

# merge and sort the per-page dictionaries into a single master
msgcat ./pot/*.pot -s --no-wrap -o dictionary.pot.new &&
	(
	cat dictionary.pot.new | 
	sed s/PACKAGE\ VERSION/squid\ 3\.0/ |
	sed s/LANGUAGE\ \<LL\@li\.org\>/Squid\ Developers\ \<squid-dev\@squid-cache\.org\>/
	) >dictionary.pot

# Update all existing dictionaries with the new content ...
for f in `ls -1 ./*.po` ; do

# NP: this does not yet fully work. Old dictionaries upgrading still needs a little work.

#	msgmerge --verbose -s --no-wrap -o ${f}.new ${f} dictionary.pot

	# TODO check that the merge actually removes translations which are now obsolete???
done
