#!/bin/sh
#
## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Orchestrates a "squid -k parse ..." test of a single Squid configuration
# file (with an optional .instructions file containing testing directions).
# Usage: test-squid-conf.sh <top_builddir> <sbindir> <squid.conf>

top_builddir=$1
sbindir=$2
configFile=$3

# If set, expect non-zero Squid exit code, with a matching stderr message
failureRegex=""

instructionsFile="$configFile.instructions"
if test -e $instructionsFile
then
    lineNo=0
    while read instructionName p1 p2
    do
        lineNo=$(($lineNo+1))
        here="$instructionsFile:$lineNo";

        if test -z "$instructionName"
        then
            continue; # skip empty lines
        fi

        if test "$instructionName" = "#"
        then
            continue; # skip comment lines
        fi

        if test "$instructionName" = "expect-failure"
        then
            if test -n "$failureRegex"
            then
                echo "$here: ERROR: Repeated $instructionName instruction";
                exit 1;
            fi

            failureRegex="$p1"

            if test -n "$p2"
            then
                echo "$here: ERROR: Bad $instructionName instruction: Unexpected second parameter: $p2";
                exit 1;
            fi

            continue;
        fi

        if test "$instructionName" = "skip-unless-autoconf-defines"
        then
            # Skip test unless the given macro is #defined in autoconf.h
            defineName=$p1

            if test -n "$p2"
            then
                echo "$here: ERROR: Bad $instructionName instruction: Unexpected second parameter: $p2";
                exit 1;
            fi

            autoconfHeader="$top_builddir/include/autoconf.h"
            if ! grep -q -w "$defineName" $autoconfHeader
            then
                echo "$here: ERROR: Bad $instructionName instruction: Unknown macro $defineName";
                exit 1;
            fi

            if grep -q "# *undef *\b$defineName\b" $autoconfHeader
            then
                echo "$here: WARNING: Skipping $configFile test because $defineName is not defined in $autoconfHeader";
                exit 0;
            fi

            if ! grep -q "# *define *\b$defineName\b" $autoconfHeader
            then
                echo "$here: ERROR: Cannot determine status of $defineName macro";
                exit 1;
            fi
        else
            echo "$here: ERROR: Unknown test-squid-conf.sh instruction name: $instructionName";
            exit 1;
        fi
    done < $instructionsFile
fi

errorLog="squid-stderr.log"

$sbindir/squid -k parse -f $configFile 2> $errorLog
result=$?

if test -z "$failureRegex"
then
    # a positive test does not require special $result interpretation
    exit $?
fi

if test "$result" -eq 0
then
    echo "ERROR: Squid successfully parsed malformed $configFile instead of rejecting it"
    exit 1;
fi

if ! grep -q -E "$failureRegex" $errorLog
then
    echo "ERROR: Squid rejected malformed $configFile but did not emit an expected message to stderr"
    echo "    expected error message regex: $failureRegex"
    echo "Squid stderr output:"
    cat $errorLog
    exit 1;
fi

echo "Squid rejected malformed $configFile as expected; Squid exit code: $result"
exit 0

