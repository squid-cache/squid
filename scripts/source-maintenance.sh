#!/bin/sh
#
## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

#
# This script contains the code run to perform automatic source maintenance
# on Squid
#

# whether to continue execution after a failure
# TODO: Expand the subset of failures covered by this feature; see run_().
KeepGoing="no"
# the actual name of the directive that enabled keep-going mode
KeepGoingDirective=""

#
# The script checks that the version of astyle is TargetAstyleVersion.
# if it isn't, the default behaviour is to not perform the formatting stage
# in order to avoid unexpected massive changes if the behaviour of astyle
# has changed in different releases.
# if --with-astyle /path/to/astyle is used, the check is still performed
# and a warning is printed, but the sources are reformatted
TargetAstyleVersion="3.1"
ASTYLE='astyle'

# whether to check and, if necessary, update boilerplate copyright years
CheckAndUpdateCopyright=yes

# How to sync CONTRIBUTORS with the current git branch commits:
# * never: Do not update CONTRIBUTORS at all.
# * auto: Check commits added since the last similar update.
# * SHA1/etc: Check commits added after the specified git commit.
UpdateContributorsSince=auto

# --only-changed-since point
OnlyChangedSince=""

printUsage () {
cat <<USAGE_
Usage: $0 [option...]
options:
--check-and-update-copyright <yes|no>      (default: yes)
--help|-h
--keep-going|-k                            (default: stop on error)
--only-changed-since <fork|commit>         (default: apply to all files)
--update-contributors-since <never|auto|revision> (default: auto)
--with-astyle </path/to/astyle/executable> (default: astyle-${TargetAstyleVersion} or astyle)

USAGE_
}

printHelp () {

cat <<HELP_INTRO_
This script applies Squid mandatory code style guidelines and generates
various files derived from Squid sources.
HELP_INTRO_

printUsage

cat <<HELP_MAIN_
--help, -h

Print this information and exit.

--only-changed-since <"fork"|commit>

When specifieid, the script only examines for formatting changes those
files that have changed since the specified git reference point. The
argument is either a git commit (fed to "git diff") or a special keyword
"fork". Common commit values include HEAD^, master, origin/master, and the
branch the current one was forked off. When "fork" is specified, the
script will look for files changed since the current branch was forked off
upstream/master (according to "git merge-base --fork-point").

This option does not disable some repository-wide file generation and
repository-wide non-formatting checks/adjustments.

--update-contributors-since <never|auto|revision>

Configures how to sync CONTRIBUTORS with the current git branch commits:
* never: Do not update CONTRIBUTORS at all.
* auto: Check commits added since the last similar update.
* SHA1/etc: Check commits added after the specified git commit.

--with-astyle </path/to/astyle/executable>

Squid code style guidelines require astyle version $TargetAstyleVersion.
The path to the astyle binary can be specified using this command line
option or by exporting the ASTYLE environment variable. If both are
specified, the command-line option wins.

External dependencies:

* Astyle. See the --with-astyle command line option above.
* gperf (if you modify certain source files)

HELP_MAIN_
}

# command-line options
while [ $# -ge 1 ]; do
    case "$1" in
    --keep-going|-k)
        KeepGoing=yes
        KeepGoingDirective=$1
        shift
        ;;
    --check-and-update-copyright)
        if test "x$2" != xyes -a "x$2" != xno
        then
            printUsage
            echo "Error: Option $1 expects a yes or no argument but got $2"
            exit 1
        fi
        CheckAndUpdateCopyright=$2
        shift 2
        ;;
    --update-contributors-since)
        if test "x$2" = x
        then
            printUsage
            echo "Error: Option $1 expects an argument."
            exit 1
        fi
        UpdateContributorsSince="$2"
        shift 2
        ;;
    --help|-h)
        printHelp
        exit 0
        ;;
    --with-astyle)
        ASTYLE=$2
        shift 2
        ;;
    --only-changed-since)
        OnlyChangedSince="$2"
        shift 2
        ;;
    *)
        printUsage
        echo "Unsupported command-line option: $1"
        exit 1
        ;;
    esac
done

# an error code seen by a KeepGoing-aware command (or zero)
SeenErrors=0

if ! git diff --quiet; then
	echo "There are unstaged changes. This script may modify sources."
	echo "Stage changes to avoid permanent losses when things go bad."
	exit 1
fi

# usage: <well-known program name> <program argument(s)> <candidate name>...
# Finds the first working program among the given candidate program names.
# The found program name is returned via the $FoundProgram global:
FoundProgram=""
findProgram() {
    wellKnown="$1"
    shift
        options="$1"
    shift

    for candidate in $*
    do
        if "$candidate" $options < /dev/null > /dev/null 2> /dev/null
        then
            echo "Found ${wellKnown}-like program: $candidate"
            FoundProgram="$candidate"
            return 0
        fi
    done

    echo "ERROR: Failed to find a ${wellKnown}-like program; tried: $*"
    FoundProgram=""
    return 1
}

made="generated" # a hack: prevents $GeneratedByMe searches matching this file
GeneratedByMe="This file is $made by scripts/source-maintenance.sh."

if [ "x$ASTYLE" != "x" ] ; then
    if ! "${ASTYLE}" --version > /dev/null 2> /dev/null ; then
        echo "ERROR: Cannot run user-supplied astyle: ${ASTYLE}"
        exit 1
    fi
else
    findProgram astyle --version astyle-${TargetAstyleVersion} astyle || exit $?
    ASTYLE=$FoundProgram
fi

ASVER=`"${ASTYLE}" --version 2>&1 | grep -o -E "[0-9.]+"`
if test "${ASVER}" != "${TargetAstyleVersion}" ; then
	if test "${ASTYLE}" = "astyle" ; then
		echo "Astyle version problem. You have ${ASVER} instead of ${TargetAstyleVersion}"
		echo "Formatting step skipped due to version mismatch"
		ASVER=""
	else
		echo "WARNING: ${ASTYLE} is version ${ASVER} instead of ${TargetAstyleVersion}"
		echo "Formatting anyway, please double check output before submitting"
	fi
else
	echo "Detected expected astyle version: ${ASVER}"
fi
CppFormatter=''
if test "${ASVER}"; then
    CppFormatter="./scripts/format-cpp.pl --with-astyle ${ASTYLE}"
fi

if test "x$OnlyChangedSince" = "xfork" ; then
    ForkPoint=`git merge-base --fork-point upstream/master`
    if test "x$ForkPoint" = "x" ; then
        echo "Could not identify fork point - sometimes it happens"
        echo "Please specify commit-id explicitly"
        exit 1
    fi
    OnlyChangedSince="$ForkPoint"
fi

if test $CheckAndUpdateCopyright = yes
then
    COPYRIGHT_YEARS=`date +"1996-%Y"`
    echo "s/1996-2[0-9]+ The Squid Software Foundation and contributors/${COPYRIGHT_YEARS} The Squid Software Foundation and contributors/g" >> boilerplate_fix.sed
fi

# executes the specified command
# in KeepGoing mode, remembers errors and hides them from callers
run_ ()
{
        "$@" && return 0 # return on success
        error=$?

        if test $KeepGoing = no; then
                return $error
        fi

        echo "ERROR: Continuing after a failure ($error) due to $KeepGoingDirective"
        SeenErrors=$error # TODO: Remember the _first_ error instead
        return 0 # hide error from the caller
}

updateIfChanged ()
{
	original="$1"
	updated="$2"
	message="$3"

	if ! cmp -s "${original}" "${updated}"; then
		echo "NOTICE: File ${original} changed: ${message}"
		run_ mv "${updated}" "${original}" || return
	else
		run_ rm -f "${updated}" || exit $?
	fi
}

# uses the given script to update the given source file
applyPlugin ()
{
        script="$1"
        source="$2"

        new="$source.new"
        $script "$source" > "$new" &&
                updateIfChanged "$source" "$new" "by $script"
}

# updates the given source file using the given script(s)
applyPluginsTo ()
{
        source="$1"
        shift

        for script in `git ls-files "$@"`; do
                run_ applyPlugin $script $source || return
        done
}

# succeeds if all MakeNamedErrorDetail() names are unique
checkMakeNamedErrorDetails ()
{
    problems=1 # assume there are problems until proven otherwise

    options='-h --only-matching --extended-regexp'
    git grep $options 'MakeNamedErrorDetail[(]".*?"[)]' src |
        sort |
        uniq --count > \
        MakeNamedErrorDetail.tmp

    if grep --quiet --word-regexp 1 MakeNamedErrorDetail.tmp; then
        if grep --invert-match --word-regexp 1 MakeNamedErrorDetail.tmp; then
            echo "ERROR: Duplicated MakeNamedErrorDetail names (see above)."
        else
            problems=0
        fi
    else
        echo "ERROR: Cannot find or process MakeNamedErrorDetail calls."
    fi

    rm MakeNamedErrorDetail.tmp # ignore (unexpected) cleanup failures
    return $problems
}

# extract IDs and gists of cache_log_message debugs() in the given source file
collectDebugMessagesFrom ()
{
    source="$1"
    destination="doc/debug-messages.tmp"

    if test "x$OnlyChangedSince" != "x"; then
        # Skipping collection due to --only-changed-since.
        # processDebugMessages() will warn.
        return 0
    fi

    # Merge multi-line debugs() into one-liners and remove '//...' comments.
    awk 'BEGIN { found=0; dbgLine=""; } {
        if ($0 ~ /[ \t]debugs[ \t]*\(/)
            found = 1;
        if (found) {
            commented = match($0, /\);[ \t]*\/\//);
            if (commented)
                $0 = substr($0, 1, RSTART+1);
            dbgLine = dbgLine $0;
        }
        if ($0 ~ /\);/) {
            if (found) {
                found = 0;
                print dbgLine;
                dbgLine = "";
            }
        }
    }' $source > doc/debug-messages.tmp2

    # sed expressions:
    # - replace debugs() prefix with the message ID contained in it
    # - remove simple parenthesized non-"string" items like (a ? b : c)
    # - replace any remaining non-"string" items with ...
    # - remove quotes around "strings"
    # - remove excessive whitespace
    # - remove debugs() statement termination sugar
    grep -o -E '\bdebugs[^,]*,[^,]*(Critical|Important)[(][0-9]+.*' doc/debug-messages.tmp2 | \
        sed -r \
            -e 's/.*(Critical|Important)[(]([0-9]+)[)][^,]*,\s*/\2 /' \
            -e 's/<<\s*[(].*[)]\s*(<<|[)];)/<< ... \1/g' \
            -e 's/<<\s*[^"]*/.../g' \
            -e 's@([^\\])"@\1@g' \
            -e 's/\s\s*/ /g' \
            -e 's/[)];$//g' \
        >> $destination

    rm -f doc/debug-messages.tmp2
}

# make doc/debug-messages.dox from aggregate collectDebugMessagesFrom results
processDebugMessages ()
{
    source="doc/debug-messages.tmp"
    destination="doc/debug-messages.dox"

    if test "x$OnlyChangedSince" != "x"; then
        echo "WARNING: Skipping update of $destination due to --only-changed-since"
        return 0
    fi

    if test '!' -s "$source"; then
        echo "ERROR: Failed to find debugs() message IDs"
        return 1
    fi

    repeatedIds=`awk '{print $1}' $source | sort -n | uniq -d`
    if test "x$repeatedIds" != "x"; then
        echo "ERROR: Repeated debugs() message IDs:"
        echo "$repeatedIds"
        echo ""
        return 1
    fi

    repeatedGists=`awk '{$1=""; print substr($0,2)}' $source | sort | uniq -d`
    if test "x$repeatedGists" != "x"; then
        echo "ERROR: Repeated debugs() message gists:"
        echo "$repeatedGists"
        echo ""
        return 1
    fi

    cat scripts/boilerplate.h > $destination
    printf '/**\n' >> $destination
    printf '\\page ControlledCacheLogMessages Message IDs and gists for cache_log_message\n' >> $destination
    printf '\\verbatim\n' >> $destination
    printf 'ID Message gist\n' >> $destination
    printf '== ============\n' >> $destination
    sort -n < $source >> $destination
    printf '\\endverbatim\n' >> $destination
    printf '*/\n' >> $destination

    rm -f $source
}

# make doc/debug-sections.txt from aggregated by srcFormat extracts
processDebugSections ()
{
    destination="doc/debug-sections.txt"

    LC_ALL=C sort -u < doc/debug-sections.tmp > doc/debug-sections.tmp2
    if test "x$OnlyChangedSince" != "x"; then
        echo "WARNING: Skipping update of $destination due to --only-changed-since"
        return 0
    fi

    cat scripts/boilerplate.h > $destination
    echo "" >> $destination
    cat doc/debug-sections.tmp2 >> $destination

    rm -f doc/debug-sections.tmp*
}

srcFormat ()
{
    # remove stale temporary files that accumulate info extracted below
    rm -f doc/debug-messages.tmp*
    rm -f doc/debug-sections.tmp*

#
# Scan for incorrect use of #ifdef/#ifndef
#
git grep "ifn?def .*_SQUID_" |
    grep -v -E "_H$" |
    grep -v "scripts/source-maintenance.sh" |
    while read f; do echo "PROBLEM?: ${f}"; done

#
# Scan for file-specific actions
#

# The two git commands below will also list any files modified during the
# current run (e.g., src/http/RegisteredHeadersHash.cci or icons/icon.am).
FilesToOperateOn=""
if test "x$OnlyChangedSince" != "x" ; then
    FilesToOperateOn=`git diff --name-only $OnlyChangedSince`
    gitResult=$?
    if test $gitResult -ne 0 ; then
        echo "ERROR: Cannot use --only-changed-since reference point: $OnlyChangedSince"
        echo "Consider using a git commit SHA (from git log) instead"
        return $gitResult
    fi
else
    FilesToOperateOn=`git ls-files`
    gitResult=$?
    # a bit paranoid but protects the empty $FilesToOperateOn check below
    if test $gitResult -ne 0 ; then
        echo "ERROR: Cannot find source code file names"
        return $gitResult
    fi
fi
if test "x$FilesToOperateOn" = "x"; then
    echo "WARNING: No files to scan and format"
    return 0
fi

for FILENAME in $FilesToOperateOn; do
    skip_copyright_check=""

    # skip subdirectories, git ls-files is recursive
    test -d $FILENAME && continue

    # generated files are formatted during their generation
    if grep -q -F "$GeneratedByMe" ${FILENAME}; then
        continue
    fi

    case ${FILENAME} in

    *.h|*.c|*.cc|*.cci)

	#
	# Code Style formatting maintenance
	#
	applyPluginsTo ${FILENAME} scripts/maintenance/ || return
	if test "$CppFormatter"; then
		if $CppFormatter $FILENAME > $FILENAME.new; then
			updateIfChanged $FILENAME $FILENAME.new 'by astyle'
		else
			rm $FILENAME.new
		fi
	fi

	#
	# REQUIRE squid.h first #include
	#
	case ${FILENAME} in
	src/cf_gen.cc)
		# ignore, this is a build tool.
		;;
	*.c|*.cc)
		FI=`grep "#include" ${FILENAME} | head -1`;
		if test "${FI}" != "#include \"squid.h\"" -a "${FILENAME}" != "cf_gen.cc"; then
			echo "ERROR: ${FILENAME} does not include squid.h first!"
		fi
		;;
	*.h|*.cci)
		FI=`grep "#include \"squid.h\"" ${FILENAME}`;
		if test "x${FI}" != "x" ; then
			echo "ERROR: ${FILENAME} duplicate include of squid.h"
		fi
		;;
	esac

	#
	# If a file includes openssl headers, then it must include compat/openssl.h
	#
	if test "${FILENAME}" != "compat/openssl.h"; then
		FA=`grep "#include.*openssl/" "${FILENAME}" 2>/dev/null | head -1`;
		FB=`grep '#include.*compat/openssl[.]h' "${FILENAME}" 2>/dev/null | head -1`;
		if test "x${FA}" != "x" -a "x${FB}" = "x"; then
			echo "ERROR: ${FILENAME} includes openssl headers without including \"compat/openssl.h\""
		fi
	fi

	#
	# forward.h means different things to Squid code depending on the path
	# require the full path is explicit for every include
	#
	FI=`grep "#include \"forward.h\"" ${FILENAME}`;
	if test "x${FI}" != "x" ; then
		echo "ERROR: ${FILENAME} contains reference to forward.h without path"
	fi

	#
	# detect functions unsafe for use within Squid.
	# strdup() - only allowed in compat/xstring.h which defines a safe replacement.
	# sprintf() - not allowed anywhere.
	#
	STRDUP=`grep -e "[^x]strdup(" ${FILENAME}`;
	if test "x${STRDUP}" != "x" -a "${FILENAME}" != "compat/xstring.h"; then
		echo "ERROR: ${FILENAME} contains unprotected use of strdup()"
	fi
	SPRINTF=`grep -e "[^v]sprintf(" ${FILENAME}`;
	if test "x${SPRINTF}" != "x" ; then
		echo "ERROR: ${FILENAME} contains unsafe use of sprintf()"
	fi

	collectDebugMessagesFrom ${FILENAME}

	#
	# DEBUG Section list maintenance
	#
	grep " DEBUG: section" <${FILENAME} | sed -e 's/ \* DEBUG: //' -e 's%/\* DEBUG: %%' -e 's% \*/%%' >> doc/debug-sections.tmp

	#
	# File permissions maintenance.
	#
	chmod 644 ${FILENAME}
	;;

    *.pl|*.sh)
	#
	# File permissions maintenance.
	#
	chmod 755 ${FILENAME}
	;;

    *.am)
        applyPluginsTo ${FILENAME} scripts/format-makefile-am.pl || return
        ;;

    ChangeLog|CREDITS|CONTRIBUTORS|COPYING|*.png|*.po|*.pot|rfcs/|*.txt|test-suite/squidconf/empty|.bzrignore)
        # we do not enforce copyright blurbs in:
        #
        #  Squid Project contributor attribution file
        #  third-party copyright attribution file
        #  images,
        #  translation PO/POT
        #  license documentation files
        #  (imported) plain-text documentation files and ChangeLogs
        #  VCS internal files
        #
        skip_copyright_check=1
        ;;
    esac

    # check for Foundation copyright blurb
    if test $CheckAndUpdateCopyright = yes -a -f ${FILENAME} -a "x$skip_copyright_check" = "x"; then
        BLURB=`grep -o "${COPYRIGHT_YEARS} The Squid Software Foundation and contributors" ${FILENAME}`;
        if test "x${BLURB}" = "x"; then
            BOILER=`grep -o -E "1996-2[0-9]+ The Squid Software Foundation and contributors" ${FILENAME}`;
            if test "x${BOILER}" != "x"; then
                echo "UPDATE COPYRIGHT for ${FILENAME}"
                sed --in-place -r -f boilerplate_fix.sed ${FILENAME}
            else
                echo "CHECK COPYRIGHT for ${FILENAME}"
            fi
        fi
    fi

done

    run_ processDebugSections || return
    run_ processDebugMessages || return
}

printRawAmFile ()
{
    sed -e 's%\ \*%##%; s%/\*%##%; s%##/%##%' < scripts/boilerplate.h

    echo "## $GeneratedByMe"
    echo

    echo -n "$1 ="
    # Only some files are formed from *.po filenames, but all such files
    # should list *.lang filenames instead.
    git ls-files $2$3 | sed -e s%$2%%g -e 's%\.po%\.lang%g' | while read f; do
        echo " \\"
        echo -n "    ${f}"
    done
    echo ""
}

generateAmFile ()
{
    amFile="$1"
    shift

    # format immediately/here instead of in srcFormat to avoid misleading
    # "NOTICE: File ... changed by scripts/format-makefile-am.pl" in srcFormat
    printRawAmFile "$@" | scripts/format-makefile-am.pl > $amFile.new

    # Distinguishing generation-only changes from formatting-only changes is
    # difficult, so we only check/report cumulative changes. Most interesting
    # changes are triggered by printRawAmFile() finding new entries.
    updateIfChanged $amFile $amFile.new 'by generateAmFile()'
}

# Build icons install include from current icons available
generateAmFile icons/icon.am ICONS "icons/" "silk/*"

# Build templates install include from current templates available
generateAmFile errors/template.am ERROR_TEMPLATES "errors/" "templates/ERR_*"

# Build errors translation install include from current .PO available
generateAmFile errors/language.am LANGUAGE_FILES "errors/" "*.po"

# Build manuals translation install include from current .PO available
generateAmFile doc/manuals/language.am LANGUAGE_FILES "doc/manuals/" "*.po"

# Build STUB framework include from current stub_* available
generateAmFile src/tests/Stub.am STUB_SOURCE "src/" "tests/stub_*.cc"

generateRawGperfFile ()
{
    gperfFile="$1"

    echo "/* $GeneratedByMe */"
    echo

    (cd `dirname $gperfFile` && gperf -m 100000 `basename $gperfFile`) | \
        sed 's@/[*]FALLTHROUGH[*]/@[[fallthrough]];@g'
}

generateGperfFile ()
{
    gperfFile="$1"
    cciFile=`echo $gperfFile | sed 's/[.]gperf$/.cci/'`

    if test $gperfFile -ot $cciFile; then
        return 0
    fi

    generateRawGperfFile $gperfFile > $cciFile.unformatted || return

    if test "$CppFormatter"; then
        # generateAmFile() explains why we format immediately/here
        $CppFormatter $cciFile.unformatted > $cciFile.new || return
        rm $cciFile.unformatted
    else
        echo "ERROR: Source code formatting disabled, but regenerated $cciFile needs formatting"
        mv $cciFile.unformatted $cciFile.new || return
    fi

    # generateAmFile() explains why we only check/report cumulative changes
    updateIfChanged $cciFile $cciFile.new 'by generateGperfFile()'
}

run_ generateGperfFile src/http/RegisteredHeadersHash.gperf || exit 1

run_ checkMakeNamedErrorDetails || exit 1

# This function updates CONTRIBUTORS based on the recent[1] branch commit log.
# Fresh contributor entries are filtered using the latest vetted CONTRIBOTORS
# file on the current branch. The following CONTRIBUTORS commits are
# considered vetted:
#
# * authored (in "git log --author" sense) by squidadm,
# * matching (in "git log --grep" sense) $vettedCommitPhraseRegex set below.
#
# A human authoring an official GitHub pull request containing a new
# CONTRIBUTORS version (that they want to be used as a new vetting point)
# should add a phrase matching $vettedCommitPhraseRegex to the PR description.
#
# [1] As defined by the --update-contributors-since script parameter.
collectAuthors ()
{
    if test "x$UpdateContributorsSince" = xnever
    then
        return 0 # successfully did nothing, as requested
    fi

    vettedCommitPhraseRegex='[Rr]eference point for automated CONTRIBUTORS updates'

    since="$UpdateContributorsSince"
    if test "x$UpdateContributorsSince" = xauto
    then
        # find the last CONTRIBUTORS commit vetted by a human
        humanSha=`git log -n1 --format='%H' --grep="$vettedCommitPhraseRegex" CONTRIBUTORS`
        # find the last CONTRIBUTORS commit attributed to this script
        botSha=`git log -n1 --format='%H' --author=squidadm CONTRIBUTORS`
        if test "x$humanSha" = x && test "x$botSha" = x
        then
            echo "ERROR: Unable to determine the commit to start contributors extraction from"
            return 1
        fi

        # find the latest commit among the above one or two commits
        if test "x$humanSha" = x
        then
            since=$botSha
        elif test "x$botSha" = x
        then
            since=$humanSha
        elif git merge-base --is-ancestor $humanSha $botSha
        then
            since=$botSha
        else
            since=$humanSha
        fi
        echo "Collecting contributors since $since"
    fi
    range="$since..HEAD"

    # We add four leading spaces below to mimic CONTRIBUTORS entry style.
    # add commit authors:
    git log --format='    %an <%ae>' $range > authors.tmp
    # add commit co-authors:
    git log $range | \
        grep -Ei '^[[:space:]]*Co-authored-by:' | \
        sed -r 's/^\s*Co-authored-by:\s*/    /i' >> authors.tmp
    # but do not add committers (--format='    %cn <%ce>').

    # add collected new (co-)authors, if any, to CONTRIBUTORS
    if ./scripts/update-contributors.pl < authors.tmp > CONTRIBUTORS.new
    then
        updateIfChanged CONTRIBUTORS CONTRIBUTORS.new  \
            "A human PR description should match: $vettedCommitPhraseRegex"
    fi
    result=$?

    rm -f authors.tmp
    return $result
}

# Update CONTRIBUTORS content
run_ collectAuthors || exit 1

# Run formatting
srcFormat || exit 1

test -e boilerplate_fix.sed && rm -f boilerplate_fix.sed

exit $SeenErrors
