#!/bin/sh
#
## Copyright (C) 2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

#
# This script runs codespell against selected files.
#

set -e

echo -n "Codespell version: "
if ! codespell --version; then
    echo "This script requires codespell which was not found."
    exit 1
fi

if ! git diff --quiet; then
    echo "There are unstaged changes. Stage these first to prevent conflict."
    exit 1
fi

WHITE_LIST=scripts/codespell-whitelist.txt
if test ! -f "${WHITE_LIST}"; then
    echo "${WHITE_LIST} does not exist"
    exit 1
fi

for FILENAME in `git ls-files`; do
    # skip subdirectories, git ls-files is recursive
    test -d $FILENAME && continue

    case ${FILENAME} in

    doc/*.txt|doc/*/*.txt)
        ;;

    *.h|*.c|*.cc|*.cci|\
    *.pl|*.sh|\
    *.pre|*.pl.in|*.pm|\
    *.dox|*.html|*.txt|\
    *.sql|\
    errors/templates/ERR_*|\
    INSTALL|README|QUICKSTART)
        #
        # Run codespell against specific file
        #
        echo "Running codespell for ${FILENAME}"
        if ! codespell -d -q 3 -w -I "${WHITE_LIST}" ${FILENAME}; then
            echo "codespell failed for ${FILENAME}"
            exit 1
	fi
        ;;
    esac
done

exit 0
