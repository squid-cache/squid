#!/bin/sh
#
## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

#
# This script uses codespell to automatically fix a subset of common spelling
# mistakes in the current git-controlled workspace.
#
# Usage: ./scripts/spell-check.sh [target]...
# ... where "target" is a git-controlled file or directory name to be fixed.
#
# By default, a hand-picked subset of Squid repository sources is fixed.
#
# See ${ALLOW_LIST} below for the list of allowed misspellings.
#

set -e

echo -n "Codespell version: "
if ! codespell --version; then
    echo "This script requires codespell which was not found."
    exit 1
fi

if ! git diff --quiet; then
    echo "There are unstaged changes. This script may modify sources."
    echo "Stage changes to avoid permanent losses when things go bad."
    exit 1
fi

IGNORE_LIST=scripts/codespell-ignorelist.txt
if test ! -f "${IGNORE_LIST}"; then
    echo "${IGNORE_LIST} does not exist"
    exit 1
fi

for FILENAME in `git ls-files "$@"`; do
    # skip subdirectories, git ls-files is recursive
    test -d $FILENAME && continue

    case ${FILENAME} in

    # skip (some) generated files with otherwise-checked extensions
    doc/debug-sections.txt)
        ;;

    # skip imported/foreign files with otherwise-checked extensions
    doc/*/*.txt)
        ;;

    # check all these
    *.h|*.c|*.cc|*.cci|\
    *.sh|\
    *.pre|\
    *.pl|*.pl.in|*.pm|\
    *.dox|*.html|*.md|*.txt|\
    *.sql|\
    errors/templates/ERR_*|\
    INSTALL|README|QUICKSTART)
        if ! codespell -d -q 3 -w -I "${IGNORE_LIST}" ${FILENAME}; then
            echo "codespell failed for ${FILENAME}"
            exit 1
	fi
        ;;
    esac
done

exit 0
