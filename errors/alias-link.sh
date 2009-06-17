#!/bin/sh
#
# Generate Symlinks for a set of aliases.
# Our base content is the bundled .po translation output
#
# This file creates the authoritative ISO aliases.
#
# INPUT:   "$(LN)" "$(RM)" "$(DESTDIR)$(DEFAULT_ERROR_DIR)" "$(srcdir)/$@"

LN="${1}"
RM="${2}"
DIR="${3}"
ALIASFILE="${4}"

if ! test -f ${ALIASFILE} ; then
	echo "FATAL: Alias file ${ALIASFILE} does not exist!"
	exit 1
fi

# Parse the alias file
cat ${ALIASFILE} |
while read base aliases; do
	# file may be commented or have empty lines
	if test "${base}" = "#" || test "${base}" = ""; then
		continue;
	fi
	# split aliases based on whitespace and create a symlink for each
	# Remove and replace any pre-existing content/link
	for alia in ${aliases}; do
		${RM} -f -r ${DIR}/${alia} || exit 1
		${LN} -s ${DIR}/${base} ${DIR}/${alia} || exit 1
	done
done
