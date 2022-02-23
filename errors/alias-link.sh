#!/bin/sh
#
## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

#
# Generate Symlinks for a set of aliases.
# Our base content is the bundled .po translation output
#
# This file creates the authoritative ISO aliases.
#

LN="${1}"
RM="${2}"
DIR="${3}"
ALIASFILE="${4}"

if ! test -f ${ALIASFILE} ; then
	echo "FATAL: Alias file ${ALIASFILE} does not exist!"
	exit 1
fi

if ! test -d ${DIR} ; then
	echo "WARNING: Destination directory does not exist. Nothing to do."
	exit 0
fi

# Parse the alias file
cat ${ALIASFILE} |
while read base aliases; do
	# file may be commented or have empty lines
	if test "${base}" = "#" || test "${base}" = ""; then
		continue;
	fi
	# ignore destination languages that do not exist. (no dead links)
	if ! test -x ${DIR}/${base} ; then
		echo "WARNING: ${base} translations do not exist. Nothing to do for: ${aliases}"
		continue;
	fi

	# split aliases based on whitespace and create a symlink for each
	# Remove and replace any pre-existing content/link
	for alia in ${aliases}; do
		${RM} -f -r ${DIR}/${alia} || exit 1
		${LN} -s ${base} ${DIR}/${alia} || exit 1
	done
done
