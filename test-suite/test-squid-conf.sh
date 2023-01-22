#!/bin/sh
#
## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

# If set to yes, expect non-zero Squid exit code,
# with stderr output matching $messageRegex.
expectFailure=no

# If set, expect a matching stderr message
messageRegex=""

expectMessage()
{
    local p1="$1"
    local p2="$2"
    local where="$3"

    if test -n "$messageRegex"
    then
        echo "$where: ERROR: Repeated message-setting instruction";
        exit 1
    fi

    messageRegex="$p1"

    if test -n "$p2"
    then
        echo "$where: ERROR: Bad message-setting instruction: Unexpected second parameter: $p2"
        exit 1
    fi
}

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
            expectFailure=yes
            expectMessage "$p1" "$p2" "$here"
            continue;
        fi

        if test "$instructionName" = "expect-message"
        then
            expectMessage "$p1" "$p2" "$here"
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

# this is the value we return to our caller;
# must be set by the code below using updateOutcome
exitCode=""
updateOutcome()
{
    local newOutcome="$1"
    # never overwrite non-zero values (i.e. only overwrite null and zero)
    if test -z "$exitCode" -o "$exitCode" = 0
    then
        exitCode="$newOutcome"
    fi
}

if test -n "$messageRegex" && ! grep -q -E "$messageRegex" $errorLog
then
    echo "ERROR: Squid did not emit an expected message to stderr"
    echo "    expected message regex: $messageRegex"
    updateOutcome 1
fi

if test $expectFailure = no
then
    if test "$result" -ne 0
    then
        echo "ERROR: Squid rejected valid $configFile; Squid exit code: $result"
        updateOutcome $result
    else
        # stay silent about ordinary success
        updateOutcome 0
    fi
else
    if test "$result" -eq 0
    then
        echo "ERROR: Squid successfully parsed malformed $configFile instead of rejecting it"
        updateOutcome 1
    else
        # stay silent about this expected failure (invisible in our output)
        #echo "Squid rejected malformed $configFile as expected; Squid exit code: $result"
        updateOutcome 0
    fi
fi

if test -z "$exitCode"
then
    echo "ERROR: BUG: Forgot to set \$exitCode: $0"
    updateOutcome 1
fi

# after a bad outcome, share Squid output
if test $exitCode -ne 0
then
    echo "Squid stderr output:"
    cat $errorLog
fi

exit $exitCode

