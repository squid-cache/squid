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

## Source Code Format Enforcement
#
# A checker to recursively reformat all source files: .h .c .cc .cci
# using a custom astyle formatter and to use md5sum (or similar) to validate
# that the formatter has not altered the code syntax.
#
# If code alteration takes place the process is halted for manual intervention.
#

# TODO: Expand the subset of failures covered by this feature; see run_().
KeepGoing="no"
# the actual name of the directive that enabled keep-going mode
KeepGoingDirective=""

# the version of astyle tool required by Squid coding style
TargetAstyleVersion="3.1"

# whether to check and, if necessary, update boilerplate copyright years
CheckAndUpdateCopyright=yes

# --update-contributors-since mode
UpdateContributorsSince=auto

# --only-changed-since point
OnlyChangedSince=""

printUsage () {
cat <<_EOF
Usage: $0 [option...]
options:
    --keep-going|-k                            (default: stop on error)
    --check-and-update-copyright <yes|no>      (default: yes)
    --update-contributors-since <never|auto|revision> (default: auto)
    --with-astyle </path/to/astyle/executable> (default: astyle-${TargetAstyleVersion} or astyle)
    --only-changed-since <fork|commit-id>      (default: apply to all files)

This script applies Squid mandatory code style guidelines.

Squid code style guidelines require astyle version $TargetAstyleVersion.
The path to the astyle binary can be specified using the
--with-astyle option or with the ASTYLE environment variable.

It will try to auto-detect a checksum program (e.g. md5sum).

If the --only-changed-since argument is supplied, it expects a git commit-id,
branch name or the special keyword 'fork'.
The script will try to only examine for formatting changes those files that
have changed since the specified commit.
The keyword 'fork' will look for files changed
since the current branch was forked off 'upstream/master'. Sensible values
for this argument may include HEAD^, master, origin/master, or the branch
the current one was forked off.
This option does not disable some repository-wide file generation and
repository-wide non-formatting checks/adjustments.

--update-contributors-since <never|auto|revision>
  Configures how to sync CONTRIBUTORS with the current git branch commits:
  * never: Do not update CONTRIBUTORS at all.
  * auto: Check commits added since the last similar update.
  * SHA1/etc: Check commits added after the specified git commit.
_EOF
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
            exit 1;
        fi
        CheckAndUpdateCopyright=$2
        shift 2
        ;;
    --update-contributors-since)
        if test "x$2" = x
        then
            printUsage
            echo "Error: Option $1 expects an argument."
            exit 1;
        fi
        UpdateContributorsSince="$2"
        shift 2;
        ;;
    --help|-h)
        printUsage
        exit 0;
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
        exit 1;
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

for Checksum in md5sum md5 shasum sha1sum false
do
    if "$Checksum" </dev/null >/dev/null 2>/dev/null ; then
        break
    fi
done
if [ "$Checksum" = "false" ]; then
    "Could not find any program to calculate a checksum such as md5sum"
    exit 1
fi
echo "detected checksum program $Checksum"

if [ "x$ASTYLE" != "x" ] ; then
    if ${ASTYLE} --version >/dev/null 2>/dev/null ; then
        :
    else
        echo "ERROR: cannot run user-supplied astyle ${ASTYLE}"
        exit 1
    fi
else
    for AttemptedBinary in astyle-${TargetAstyleVersion} astyle
    do
        if $AttemptedBinary --version >/dev/null 2>/dev/null ; then
            ASTYLE=$AttemptedBinary
            echo "detected astyle program ${ASTYLE}"
            break
        fi
    done
    if [ -z "${ASTYLE}" ]; then
        echo "cannot find any installed astyle program"
        exit 1
    fi
fi

${ASTYLE} --version >/dev/null 2>/dev/null
result=$?
if test $result -gt 0 ; then
	echo "ERROR: cannot run ${ASTYLE}"
	exit 1
fi
ASVER=`${ASTYLE} --version 2>&1 | grep -o -E "[0-9.]+"`
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
	echo "Found astyle ${ASVER}"
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
        "$@" && return; # return on success
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
        return 0;
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
        return 0;
    fi

    if test '!' -s "$source"; then
        echo "ERROR: Failed to find debugs() message IDs"
        return 1;
    fi

    repeatedIds=`awk '{print $1}' $source | sort -n | uniq -d`
    if test "x$repeatedIds" != "x"; then
        echo "ERROR: Repeated debugs() message IDs:"
        echo "$repeatedIds"
        echo ""
        return 1;
    fi

    repeatedGists=`awk '{$1=""; print substr($0,2)}' $source | sort | uniq -d`
    if test "x$repeatedGists" != "x"; then
        echo "ERROR: Repeated debugs() message gists:"
        echo "$repeatedGists"
        echo ""
        return 1;
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

    if test "x$OnlyChangedSince" != "x"; then
        echo "WARNING: Skipping update of $destination due to --only-changed-since"
        return 0;
    fi

    sort -u < doc/debug-sections.tmp | sort -n > doc/debug-sections.tmp2
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

ForkPoint=""
if test "x$OnlyChangedSince" = "xfork" ; then
    ForkPoint=`git merge-base --fork-point upstream/master`
    if test "x$ForkPoint" = "x" ; then
        echo "Could not identify fork point - sometimes it happens"
        echo "Please specify commit-id explicitly"
        exit 1
    fi
    OnlyChangedSince="$ForkPoint"
fi

FilesToOperateOn=""
if test "x$OnlyChangedSince" != "x" ; then
    FilesToOperateOn=`git diff --name-only $OnlyChangedSince`
else
    FilesToOperateOn=`git ls-files`
fi

for FILENAME in $FilesToOperateOn; do
    skip_copyright_check=""

    # skip subdirectories, git ls-files is recursive
    test -d $FILENAME && continue

    case ${FILENAME} in

    *.h|*.c|*.cc|*.cci)

	#
	# Code Style formatting maintenance
	#
	applyPluginsTo ${FILENAME} scripts/maintenance/ || return
	if test "${ASVER}"; then
		./scripts/formater.pl --with-astyle ${ASTYLE} ${FILENAME}
		if test -e $FILENAME -a -e "$FILENAME.astylebak"; then
			md51=`cat  $FILENAME| tr -d "\n \t\r" | $Checksum`;
			md52=`cat  $FILENAME.astylebak| tr -d "\n \t\r" | $Checksum`;

			if test "$md51" != "$md52"; then
				echo "ERROR: File $FILENAME not formatting well";
				mv $FILENAME $FILENAME.astylebad
				mv $FILENAME.astylebak $FILENAME
				git checkout -- ${FILENAME}
			else
				rm -f $FILENAME.astylebak
			fi
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
	grep " DEBUG: section" <${FILENAME} | sed -e 's/ \* DEBUG: //' -e 's%/\* DEBUG: %%' -e 's% \*/%%' | sort -u >>doc/debug-sections.tmp

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

printAmFile ()
{
    sed -e 's%\ \*%##%; s%/\*%##%; s%##/%##%' < scripts/boilerplate.h
    echo -n "$1 ="
    git ls-files $2$3 | sed -e s%$2%%g | sort -u | while read f; do
        echo " \\"
        echo -n "    ${f}"
    done
    echo ""
}

# Build icons install include from current icons available
printAmFile ICONS "icons/" "silk/*" > icons/icon.am

# Build templates install include from current templates available
printAmFile ERROR_TEMPLATES "errors/" "templates/ERR_*" > errors/template.am

# Build errors translation install include from current .PO available
printAmFile TRANSLATE_LANGUAGES "errors/" "*.po" | sed 's%\.po%\.lang%g' > errors/language.am

# Build manuals translation install include from current .PO available
printAmFile TRANSLATE_LANGUAGES "doc/manuals/" "*.po" | sed 's%\.po%\.lang%g' > doc/manuals/language.am

# Build STUB framework include from current stub_* available
printAmFile STUB_SOURCE "src/" "tests/stub_*.cc" > src/tests/Stub.am

# Build the GPERF generated content
make -C src/http gperf-files

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
        return 0; # successfully did nothing, as requested
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
            return 1;
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

rm -f boilerplate_fix.sed

exit $SeenErrors
